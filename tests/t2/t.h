struct a;
struct b;

struct a {
	struct b *b;
};

struct b {
	struct a *a;
};
