/*
 * MIT License
 *
 * Copyright (c) 2018 XMM SWAP LTD
 */

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#include <lua.h>
#include <lauxlib.h>

#include <libelf.h>

#define ELF_MT "elftoolchain::Elf"
#define ELF_SCN_MT "elftoolchain::Elf_Scn"
#define ELF_ARSYM_MT "elftoolchain::Elf_Arsym"

struct udataElf {
	Elf *elf;
	void *ehdr; /* Elf64_Ehdr or Elf32_Ehdr. */
	void *mem; /* XXX implement */
	int fd;
	int flags;
#define EHDR64 1
};

static int
elf_is_closed(lua_State *L, int arg)
{
	const char *errmsg = "Elf object is closed";

	if (arg < 0)
		return luaL_error(L, errmsg);
	else
		return luaL_argerror(L, arg, errmsg);
}

static struct udataElf *
check_elf_udata(lua_State *L, int arg, int err_arg)
{
	struct udataElf *ud;

	ud = (struct udataElf *)luaL_checkudata(L, arg, ELF_MT);
	if (ud->elf == NULL)
		elf_is_closed(L, err_arg);

	return ud;
}

static Elf_Scn **
test_elf_scn_udata(lua_State *L, int arg)
{

	return (Elf_Scn **)luaL_testudata(L, arg, ELF_SCN_MT);
}

static Elf_Scn **
check_elf_scn_udata(lua_State *L, int arg)
{

	return (Elf_Scn **)luaL_checkudata(L, arg, ELF_SCN_MT);
}

static int
l_elf_begin(lua_State *L)
{
	struct udataElf *ud;
	const char *filename, *errmsg;
	int err;

	filename = luaL_checkstring(L, 1);

	ud = (struct udataElf *)lua_newuserdata(L, sizeof(struct udataElf));
	ud->elf = NULL;
	ud->ehdr = NULL;
	ud->mem = NULL;
	ud->flags = 0;

	luaL_getmetatable(L, ELF_MT);
	lua_setmetatable(L, -2);

	if ((ud->fd = open(filename, O_RDONLY | O_CLOEXEC)) == -1) {
		err = errno;
		errmsg = (const char *)strerror(err);
		goto err;
	}

	if ((ud->elf = elf_begin(ud->fd, ELF_C_READ, NULL)) == NULL) {
		err = elf_errno();
		errmsg = elf_errmsg(err);
		goto err;
	}

	return 1;
err:
	lua_pushnil(L);
	lua_pushstring(L, errmsg ? errmsg : "no error");
	lua_pushinteger(L, err); /* XXX Is it C errno or Elf errno? */

	return 3;
}

/*
 * XXX Extract EI_CLASS EI_DATA EI_VERSION EI_OSABI EI_ABIVERSION from e_ident.
 * XXX Convert e_type and e_machine to strings.
 */
static int
init_ehdr_push(lua_State *L, struct udataElf *ud, int elf_arg)
{
	int err;

	assert(ud->ehdr == NULL);

	ud->ehdr = elf32_getehdr(ud->elf);
	err = elf_errno();

	if (ud->ehdr == NULL && err == ELF_E_CLASS) {
		ud->ehdr = elf64_getehdr(ud->elf);
		err = elf_errno();

		if (ud->ehdr != NULL)
			ud->flags |= EHDR64;
	}

	if (ud->ehdr == NULL) {
		lua_pushnil(L);
		lua_pushstring(L, elf_errmsg(err));
		lua_pushinteger(L, err);
		return 3;
	}

	lua_createtable(L, 0, 15);

	if (ud->flags & EHDR64) {
		Elf64_Ehdr *h = ud->ehdr;

		lua_pushstring(L, "ELFCLASS64");
		lua_setfield(L, -2, "class");
		lua_pushlstring(L, (const char *)h->e_ident, ELF_NIDENT);
		lua_setfield(L, -2, "ident");	/* Id bytes */
		lua_pushinteger(L, h->e_type);
		lua_setfield(L, -2, "type");	/* file type */
		lua_pushinteger(L, h->e_machine);
		lua_setfield(L, -2, "machine");	/* machine type */
		lua_pushinteger(L, h->e_version);
		lua_setfield(L, -2, "version");	/* version number */
		lua_pushinteger(L, h->e_entry);
		lua_setfield(L, -2, "entry");	/* entry point */
		lua_pushinteger(L, h->e_phoff);
		lua_setfield(L, -2, "phoff");	/* Program hdr offset */
		lua_pushinteger(L, h->e_shoff);
		lua_setfield(L, -2, "shoff");	/* Section hdr offset */
		lua_pushinteger(L, h->e_flags);
		lua_setfield(L, -2, "flags");	/* Processor flags */
		lua_pushinteger(L, h->e_ehsize);
		lua_setfield(L, -2, "ehsize");	/* sizeof ehdr */
		lua_pushinteger(L, h->e_phentsize);
		lua_setfield(L, -2, "phentsize");/* Program header entry size */
		lua_pushinteger(L, h->e_phnum);
		lua_setfield(L, -2, "phnum");	/* Number of program headers */
		lua_pushinteger(L, h->e_shentsize);
		lua_setfield(L, -2, "shentsize");/* Section header entry size */
		lua_pushinteger(L, h->e_shnum);
		lua_setfield(L, -2, "shnum");	/* Number of section headers */
		lua_pushinteger(L, h->e_shstrndx);
		lua_setfield(L, -2, "shstrndx");/* String table index */
	} else {
		Elf32_Ehdr *h = ud->ehdr;

		lua_pushstring(L, "ELFCLASS32");
		lua_setfield(L, -2, "class");
		lua_pushlstring(L, (const char *)h->e_ident, ELF_NIDENT);
		lua_setfield(L, -2, "ident");	/* Id bytes */
		lua_pushinteger(L, h->e_type);
		lua_setfield(L, -2, "type");	/* file type */
		lua_pushinteger(L, h->e_machine);
		lua_setfield(L, -2, "machine");	/* machine type */
		lua_pushinteger(L, h->e_version);
		lua_setfield(L, -2, "version");	/* version number */
		lua_pushinteger(L, h->e_entry);
		lua_setfield(L, -2, "entry");	/* entry point */
		lua_pushinteger(L, h->e_phoff);
		lua_setfield(L, -2, "phoff");	/* Program hdr offset */
		lua_pushinteger(L, h->e_shoff);
		lua_setfield(L, -2, "shoff");	/* Section hdr offset */
		lua_pushinteger(L, h->e_flags);
		lua_setfield(L, -2, "flags");	/* Processor flags */
		lua_pushinteger(L, h->e_ehsize);
		lua_setfield(L, -2, "ehsize");	/* sizeof ehdr */
		lua_pushinteger(L, h->e_phentsize);
		lua_setfield(L, -2, "phentsize");/* Program header entry size */
		lua_pushinteger(L, h->e_phnum);
		lua_setfield(L, -2, "phnum");	/* Number of program headers */
		lua_pushinteger(L, h->e_shentsize);
		lua_setfield(L, -2, "shentsize");/* Section header entry size */
		lua_pushinteger(L, h->e_shnum);
		lua_setfield(L, -2, "shnum");	/* Number of section headers */
		lua_pushinteger(L, h->e_shstrndx);
		lua_setfield(L, -2, "shstrndx");/* String table index */
	}

	/* Cache in userdata. */
	lua_pushvalue(L, -1);
	lua_setuservalue(L, elf_arg);

	return 1;
}

static int
l_elf_getehdr(lua_State *L)
{
	struct udataElf *ud;

	ud = check_elf_udata(L, 1, 1);

	if (ud->ehdr != NULL) {
		/* Already cached in userdata. */
		lua_getuservalue(L, 1);
		return 1;
	}

	return init_ehdr_push(L, ud, 1);
}

static int
l_elf_class(lua_State *L)
{
	struct udataElf *ud;
	int num_pushed;

	ud = check_elf_udata(L, 1, 1);

	if (ud->ehdr == NULL && (num_pushed = init_ehdr_push(L, ud, 1)) > 1)
		return num_pushed; /* nil, errmsg, errno. */

	assert(ud->ehdr != NULL);

	lua_pushstring(L, (ud->flags & EHDR64) ? "ELFCLASS64" : "ELFCLASS32");

	return 1;
}

static int
l_elf_ident(lua_State *L)
{
	struct udataElf *ud;
	int num_pushed;

	ud = check_elf_udata(L, 1, 1);

	if (ud->ehdr == NULL && (num_pushed = init_ehdr_push(L, ud, 1)) > 1)
		return num_pushed; /* nil, errmsg, errno. */

	assert(ud->ehdr != NULL);

	if (ud->flags & EHDR64) {
		Elf64_Ehdr *h = ud->ehdr;

		lua_pushlstring(L, (const char *)h->e_ident, ELF_NIDENT);
	} else {
		Elf32_Ehdr *h = ud->ehdr;

		lua_pushlstring(L, (const char *)h->e_ident, ELF_NIDENT);
	}

	return 1;
}

static int
l_elf_type(lua_State *L)
{
	struct udataElf *ud;
	int num_pushed;

	ud = check_elf_udata(L, 1, 1);

	if (ud->ehdr == NULL && (num_pushed = init_ehdr_push(L, ud, 1)) > 1)
		return num_pushed; /* nil, errmsg, errno. */

	assert(ud->ehdr != NULL);

	if (ud->flags & EHDR64) {
		Elf64_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_type);
	} else {
		Elf32_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_type);
	}

	return 1;
}

static int
l_elf_machine(lua_State *L)
{
	struct udataElf *ud;
	int num_pushed;

	ud = check_elf_udata(L, 1, 1);

	if (ud->ehdr == NULL && (num_pushed = init_ehdr_push(L, ud, 1)) > 1)
		return num_pushed; /* nil, errmsg, errno. */

	assert(ud->ehdr != NULL);

	if (ud->flags & EHDR64) {
		Elf64_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_machine);
	} else {
		Elf32_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_machine);
	}

	return 1;
}

static int
l_elf_version(lua_State *L)
{
	struct udataElf *ud;
	int num_pushed;

	ud = check_elf_udata(L, 1, 1);

	if (ud->ehdr == NULL && (num_pushed = init_ehdr_push(L, ud, 1)) > 1)
		return num_pushed; /* nil, errmsg, errno. */

	assert(ud->ehdr != NULL);

	if (ud->flags & EHDR64) {
		Elf64_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_version);
	} else {
		Elf32_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_version);
	}

	return 1;
}

static int
l_elf_entry(lua_State *L)
{
	struct udataElf *ud;
	int num_pushed;

	ud = check_elf_udata(L, 1, 1);

	if (ud->ehdr == NULL && (num_pushed = init_ehdr_push(L, ud, 1)) > 1)
		return num_pushed; /* nil, errmsg, errno. */

	assert(ud->ehdr != NULL);

	if (ud->flags & EHDR64) {
		Elf64_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_entry);
	} else {
		Elf32_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_entry);
	}

	return 1;
}

static int
l_elf_phoff(lua_State *L)
{
	struct udataElf *ud;
	int num_pushed;

	ud = check_elf_udata(L, 1, 1);

	if (ud->ehdr == NULL && (num_pushed = init_ehdr_push(L, ud, 1)) > 1)
		return num_pushed; /* nil, errmsg, errno. */

	assert(ud->ehdr != NULL);

	if (ud->flags & EHDR64) {
		Elf64_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_phoff);
	} else {
		Elf32_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_phoff);
	}

	return 1;
}

static int
l_elf_shoff(lua_State *L)
{
	struct udataElf *ud;
	int num_pushed;

	ud = check_elf_udata(L, 1, 1);

	if (ud->ehdr == NULL && (num_pushed = init_ehdr_push(L, ud, 1)) > 1)
		return num_pushed; /* nil, errmsg, errno. */

	assert(ud->ehdr != NULL);

	if (ud->flags & EHDR64) {
		Elf64_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_shoff);
	} else {
		Elf32_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_shoff);
	}

	return 1;
}

static int
l_elf_flags(lua_State *L)
{
	struct udataElf *ud;
	int num_pushed;

	ud = check_elf_udata(L, 1, 1);

	if (ud->ehdr == NULL && (num_pushed = init_ehdr_push(L, ud, 1)) > 1)
		return num_pushed; /* nil, errmsg, errno. */

	assert(ud->ehdr != NULL);

	if (ud->flags & EHDR64) {
		Elf64_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_flags);
	} else {
		Elf32_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_flags);
	}

	return 1;
}

static int
l_elf_ehsize(lua_State *L)
{
	struct udataElf *ud;
	int num_pushed;

	ud = check_elf_udata(L, 1, 1);

	if (ud->ehdr == NULL && (num_pushed = init_ehdr_push(L, ud, 1)) > 1)
		return num_pushed; /* nil, errmsg, errno. */

	assert(ud->ehdr != NULL);

	if (ud->flags & EHDR64) {
		Elf64_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_ehsize);
	} else {
		Elf32_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_ehsize);
	}

	return 1;
}

static int
l_elf_phentsize(lua_State *L)
{
	struct udataElf *ud;
	int num_pushed;

	ud = check_elf_udata(L, 1, 1);

	if (ud->ehdr == NULL && (num_pushed = init_ehdr_push(L, ud, 1)) > 1)
		return num_pushed; /* nil, errmsg, errno. */

	assert(ud->ehdr != NULL);

	if (ud->flags & EHDR64) {
		Elf64_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_phentsize);
	} else {
		Elf32_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_phentsize);
	}

	return 1;
}

static int
l_elf_phnum(lua_State *L)
{
	struct udataElf *ud;
	int num_pushed;

	ud = check_elf_udata(L, 1, 1);

	if (ud->ehdr == NULL && (num_pushed = init_ehdr_push(L, ud, 1)) > 1)
		return num_pushed; /* nil, errmsg, errno. */

	assert(ud->ehdr != NULL);

	if (ud->flags & EHDR64) {
		Elf64_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_phnum);
	} else {
		Elf32_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_phnum);
	}

	return 1;
}

static int
l_elf_shentsize(lua_State *L)
{
	struct udataElf *ud;
	int num_pushed;

	ud = check_elf_udata(L, 1, 1);

	if (ud->ehdr == NULL && (num_pushed = init_ehdr_push(L, ud, 1)) > 1)
		return num_pushed; /* nil, errmsg, errno. */

	assert(ud->ehdr != NULL);

	if (ud->flags & EHDR64) {
		Elf64_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_shentsize);
	} else {
		Elf32_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_shentsize);
	}

	return 1;
}

static int
l_elf_shnum(lua_State *L)
{
	struct udataElf *ud;
	int num_pushed;

	ud = check_elf_udata(L, 1, 1);

	if (ud->ehdr == NULL && (num_pushed = init_ehdr_push(L, ud, 1)) > 1)
		return num_pushed; /* nil, errmsg, errno. */

	assert(ud->ehdr != NULL);

	if (ud->flags & EHDR64) {
		Elf64_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_shnum);
	} else {
		Elf32_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_shnum);
	}

	return 1;
}

static int
l_elf_shstrndx(lua_State *L)
{
	struct udataElf *ud;
	int num_pushed;

	ud = check_elf_udata(L, 1, 1);

	if (ud->ehdr == NULL && (num_pushed = init_ehdr_push(L, ud, 1)) > 1)
		return num_pushed; /* nil, errmsg, errno. */

	assert(ud->ehdr != NULL);

	if (ud->flags & EHDR64) {
		Elf64_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_shstrndx);
	} else {
		Elf32_Ehdr *h = ud->ehdr;

		lua_pushinteger(L, h->e_shstrndx);
	}

	return 1;
}

static int
l_elf_gc(lua_State *L)
{
	struct udataElf *ud;

	ud = check_elf_udata(L, 1, 1);

	if (ud->elf) {
		elf_end(ud->elf); /* XXX elf_end returns refcount. */
		ud->elf = NULL;
	}

	if (ud->fd >= 0) {
		close(ud->fd);
		ud->fd = -1;
	}

	return 0;
}

static int
l_elf_tostring(lua_State *L)
{
	struct udataElf *ud;

	ud = check_elf_udata(L, 1, 1);

	lua_pushfstring(L, "Elf%s@%p", ud->elf ? "" : "(closed)", ud);

	return 1;
}

/*
 * Call elf_nextscn(3), wrap the returned object and push it to the L's stack.
 * Uservalue of the pushed object is set to its parent Elf object at elf_arg.
 */
static int
nextscn_push(lua_State *L, Elf *elf, Elf_Scn *scn, int elf_arg)
{
	Elf_Scn **ud;

	/* XXX Documentation isn't clear about how to detect an error. */
	scn = elf_nextscn(elf, scn);

	if (scn == NULL) {
		lua_pushnil(L);
		return 1;
	}

	ud = (Elf_Scn **)lua_newuserdata(L, sizeof(Elf_Scn *));
	*ud = NULL;

	luaL_getmetatable(L, ELF_SCN_MT);
	lua_setmetatable(L, -2);

	/* Keep a reference to the parent Elf object. */
	assert(luaL_testudata(L, elf_arg, ELF_MT) != NULL);
	lua_pushvalue(L, elf_arg);
	lua_setuservalue(L, -2);

	*ud = scn;

	return 1;
}

static int
l_elf_nextscn(lua_State *L)
{
	struct udataElf *elf;
	Elf_Scn *scn, **ud;

	elf = check_elf_udata(L, 1, 1);
	ud = test_elf_scn_udata(L, 2);
	scn = ud ? *ud : NULL;

	if (ud != NULL) {
		lua_getuservalue(L, 2);
		if (lua_touserdata(L, -1) != elf)
			return luaL_argerror(L, 2, "different parent");
	}

	return nextscn_push(L, elf->elf, scn, 1);
}

/*
 * Return an iterator over Elf_Scn objects:
 *
 *	for scn in elf:scn() do	... end
 */
static int
l_elf_scn(lua_State *L)
{

	lua_pushcfunction(L, &l_elf_nextscn);
	lua_pushvalue(L, 1);

	return 2;
}

static int
l_elf_scn_next(lua_State *L)
{
	Elf_Scn *scn, **ud;
	struct udataElf *elf;

	ud = check_elf_scn_udata(L, 1);
	scn = *ud;

	lua_getuservalue(L, 1);
	elf = check_elf_udata(L, -1, 1);

	return nextscn_push(L, elf->elf, scn, lua_gettop(L));
}

static int
l_elf_scn_tostring(lua_State *L)
{
	Elf_Scn **ud;

	ud = test_elf_scn_udata(L, 1);

	lua_pushfstring(L, "Elf_Scn%s@%p", *ud ? "" : "(inactive)", ud);

	return 1;
}

static void
register_index(lua_State *L, luaL_Reg index[])
{

	lua_pushstring(L, "__index");
	lua_newtable(L);
	luaL_setfuncs(L, index, 0);
	lua_rawset(L, -3);
}

static luaL_Reg elftoolchain[] = {
	{ "begin", l_elf_begin },
	{ "elf_end", l_elf_gc },
	{ "nextscn", l_elf_nextscn },
	{ "getehdr", l_elf_getehdr },
	{ "class", l_elf_class },
	{ "ident", l_elf_ident },
	{ "type", l_elf_type },
	{ "machine", l_elf_machine },
	{ "version", l_elf_version },
	{ "entry", l_elf_entry },
	{ "phoff", l_elf_phoff },
	{ "shoff", l_elf_shoff },
	{ "flags", l_elf_flags },
	{ "ehsize", l_elf_ehsize },
	{ "phentsize", l_elf_phentsize },
	{ "phnum", l_elf_phnum },
	{ "shentsize", l_elf_shentsize },
	{ "shnum", l_elf_shnum },
	{ "shstrndx", l_elf_shstrndx },
	{ NULL, NULL }
};

static luaL_Reg elf_mt[] = {
	{ "__gc", l_elf_gc },
	{ "__tostring", l_elf_tostring },
	{ NULL, NULL }
};

static luaL_Reg elf_index[] = {
	{ "close", l_elf_gc },
	{ "nextscn", l_elf_nextscn },
	{ "scn", l_elf_scn },
	{ "getehdr", l_elf_getehdr },
	{ "ident", l_elf_ident },
	{ "type", l_elf_type },
	{ "machine", l_elf_machine },
	{ "version", l_elf_version },
	{ "entry", l_elf_entry },
	{ "phoff", l_elf_phoff },
	{ "shoff", l_elf_shoff },
	{ "flags", l_elf_flags },
	{ "ehsize", l_elf_ehsize },
	{ "phentsize", l_elf_phentsize },
	{ "phnum", l_elf_phnum },
	{ "shentsize", l_elf_shentsize },
	{ "shnum", l_elf_shnum },
	{ "shstrndx", l_elf_shstrndx },
	{ NULL, NULL }
};

static luaL_Reg elf_scn_mt[] = {
	{ "__tostring", l_elf_scn_tostring },
	{ NULL, NULL }
};

static luaL_Reg elf_scn_index[] = {
	{ "next", l_elf_scn_next },
	{ NULL, NULL }
};

int
luaopen_elftoolchain(lua_State *L)
{
	if (elf_version(EV_CURRENT) == EV_NONE)
		return luaL_error(L, "ELF library is too old");

	luaL_newmetatable(L, ELF_MT);
	luaL_setfuncs(L, elf_mt, 0);
	register_index(L, elf_index);

	luaL_newmetatable(L, ELF_SCN_MT);
	luaL_setfuncs(L, elf_scn_mt, 0);
	register_index(L, elf_scn_index);

	luaL_newlibtable(L, elftoolchain);
	luaL_setfuncs(L, elftoolchain, 0);

	return 1;
}
