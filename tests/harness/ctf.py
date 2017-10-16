from StringIO import StringIO
import zlib

from elftools.construct import (
    UNInt8, UNInt16, UNInt32, UNInt64, SNInt32,
    CString, IfThenElse, MetaArray, Pass, Pointer, Struct, Switch, Union
)

CTF_MAGIC = 0xcff1
CTF_FLAG_MASK = 0x1
CTF_VERSION = 2

CTF_KIND_UNKNOWN = 0
CTF_KIND_INTEGER = 1
CTF_KIND_FLOAT = 2
CTF_KIND_POINTER = 3
CTF_KIND_ARRAY = 4
CTF_KIND_FUNCTION = 5
CTF_KIND_STRUCT = 6
CTF_KIND_UNION = 7
CTF_KIND_ENUM = 8
CTF_KIND_FORWARD = 9
CTF_KIND_TYPEDEF = 10
CTF_KIND_VOLATILE = 11
CTF_KIND_CONST = 12
CTF_KIND_RESTRICT = 13

CTF_LSTRUCT_THRESH = 8192
CTF_MAX_SIZE = 0xfffe
CTF_MAX_VLEN = 0x03ff

def CTF_INFO_KIND(info):
    return (info & 0xf800) >> 11
def CTF_INFO_VLEN(info):
    return info & CTF_MAX_VLEN

class CTFError(Exception):
    pass

class CTF_FLAGS(object):
    CTF_F_COMPRESS = 0x1

class CTFStructs(object):
    def __init__(self, stroff):
        self._stroff = stroff
        self._create_types()

    def _create_types(self):
        self.ctf_type = Struct(
            'ctf_type',
            UNInt32('_ctt_name'),
            Pointer(lambda ctx : ctx._ctt_name + self._stroff,
                    CString('ctt_name')),
            UNInt16('ctt_info'),
            Union('ST',
                  UNInt16('ctt_size'),
                  UNInt16('ctt_type')),
            IfThenElse(
                'ctt_lsize',
                lambda ctx: ctx.ST.ctt_size > CTF_MAX_SIZE,
                Struct('LS', UNInt32('ctt_lsizehi'), UNInt32('ctt_lsizelo')),
                Pass),
            Switch(
                'ctt_typeinfo',
                lambda ctx: CTF_INFO_KIND(ctx.ctt_info),
                {
                    CTF_KIND_INTEGER : self._create_integer(),
                    CTF_KIND_FLOAT : self._create_float(),
                    CTF_KIND_ARRAY : self._create_array(),
                    CTF_KIND_FUNCTION : self._create_function(),
                    CTF_KIND_STRUCT : self._create_struct(),
                    CTF_KIND_UNION : self._create_union(),
                    CTF_KIND_ENUM : self._create_enum()
                },
                default=Pass))

    def _create_integer(self):
        return Struct('ctt_integer', UNInt32('cti_encoding'))

    def _create_float(self):
        return Struct('ctt_float', UNInt32('ctf_encoding'))

    def _create_array(self):
        return Struct('ctt_array',
                      UNInt16('cta_contents'),
                      UNInt16('cta_index'),
                      UNInt32('cta_nelems'))

    def _create_function(self):
        return Struct('ctt_function',
                      MetaArray(lambda ctx : CTF_INFO_VLEN(ctx._.ctt_info) +
                                             (CTF_INFO_VLEN(ctx._.ctt_info) & 1),
                                UNInt16('ctf_args')))

    def _create_sou_members(self):
        return IfThenElse(
            'ctt_members',
            lambda ctx : ctx._.ST.ctt_size >= CTF_LSTRUCT_THRESH,
            MetaArray(lambda ctx : CTF_INFO_VLEN(ctx._.ctt_info),
                      Struct('ctf_lmember',
                             UNInt32('_ctlm_name'),
                             Pointer(lambda ctx : ctx._ctlm_name +
                                                  self._stroff,
                                     CString('ctlm_name')),
                             UNInt16('ctlm_type'),
                             UNInt16('ctlm_pad'),
                             UNInt32('ctlm_offsethi'),
                             UNInt32('ctlm_offsetlo'))),
            MetaArray(lambda ctx : CTF_INFO_VLEN(ctx._.ctt_info),
                      Struct('ctf_member',
                             UNInt32('_ctm_name'),
                             Pointer(lambda ctx : ctx._ctm_name +
                                                  self._stroff,
                                     CString('ctm_name')),
                             UNInt16('ctm_type'),
                             UNInt16('ctm_offset'))))

    def _create_struct(self):
        return Struct('ctt_struct', self._create_sou_members())

    def _create_union(self):
        return Struct('ctt_union', self._create_sou_members())

    def _create_enum(self):
        return Struct('ctt_enum',
                      MetaArray(lambda ctx : CTF_INFO_VLEN(ctx._.ctt_info),
                      Struct('ctt_members',
                             UNInt32('_cte_name'),
                             Pointer(lambda ctx : ctx._cte_name +
                                                  self._stroff,
                                     CString('cte_name')),
                             SNInt32('cte_value'))))

class CTFFile(object):
    def __init__(self, stream):
        self._create_header_struct()
        stream.seek(0)
        self.header = self._ctf_header.parse_stream(stream)

        if self.header['cth_magic'] != CTF_MAGIC:
            raise CTFError("Incorrect magic number")
        if self.header['cth_version'] != 2:
            raise CTFError("Unknown or invalid CTF version")
        if self.header['cth_flags'] & ~CTF_FLAG_MASK != 0:
            raise CTFError("Unknown CTF flags")

        self.ischild = self.header['cth_parname'] != 0

        data = stream.read()
        if self.header['cth_flags'] & CTF_FLAGS.CTF_F_COMPRESS != 0:
            data = zlib.decompress(data)
        self.stream = StringIO(data)

        self.structs = CTFStructs(self.header['cth_stroff'])

    def _create_header_struct(self):
        self._ctf_header = Struct(
            'ctf_header',
            UNInt16('cth_magic'),
            UNInt8('cth_version'),
            UNInt8('cth_flags'),
            UNInt32('cth_parlabel'),
            UNInt32('cth_parname'),
            UNInt32('cth_lbloff'),
            UNInt32('cth_objtoff'),
            UNInt32('cth_funcoff'),
            UNInt32('cth_typeoff'),
            UNInt32('cth_stroff'),
            UNInt32('cth_strlen'))

    def get_type(self, index):
        i = 1
        for t in self.iter_types():
            if i == index:
                return t
            i += 1
        else:
            raise CTFError("Index out of bounds")

    def iter_types(self):
        self.stream.seek(self.header['cth_typeoff'])
        while self.stream.tell() < self.header['cth_stroff']:
            yield self.structs.ctf_type.parse_stream(self.stream)
