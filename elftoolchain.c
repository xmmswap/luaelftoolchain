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
	void *mem; /* XXX implement */
	int fd;
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
	ud->mem = NULL;

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
	{ NULL, NULL }
};

static luaL_Reg elf_mt[] = {
	{ "__gc", l_elf_gc },
	{ "__tostring", l_elf_tostring },
	{ NULL, NULL }
};

static luaL_Reg elf_index[] = {
	{ "nextscn", l_elf_nextscn },
	{ "scn", l_elf_scn },
	{ "close", l_elf_gc },
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

	luaL_newlib(L, elftoolchain);

	return 1;
}
