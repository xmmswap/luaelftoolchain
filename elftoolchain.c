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

struct KV {
	lua_Integer key;
	const char *val;
};

/* e_type values. */
static const struct KV et_constants[] = {
	{ ET_NONE, "NONE" },
	{ ET_REL,  "REL"  },
	{ ET_EXEC, "EXEC" },
	{ ET_DYN,  "DYN"  },
	{ ET_CORE, "CORE" },
	{ 0, NULL }
};

/* e_machine values. */
static const struct KV em_constants[] = {
	{ EM_NONE, "NONE" },
	{ EM_M32, "M32" },
	{ EM_SPARC, "SPARC" },
	{ EM_386, "386" },
	{ EM_68K, "68K" },
	{ EM_88K, "88K" },
	{ EM_486, "486" },
	{ EM_IAMCU, "IAMCU" },
	{ EM_860, "860" },
	{ EM_MIPS, "MIPS" },
	{ EM_S370, "S370" },
	{ EM_MIPS_RS3_LE, "MIPS_RS3_LE" },
	{ EM_RS6000, "RS6000" },
	{ EM_PARISC, "PARISC" },
	{ EM_NCUBE, "NCUBE" },
	{ EM_VPP500, "VPP500" },
	{ EM_SPARC32PLUS, "SPARC32PLUS" },
	{ EM_960, "960" },
	{ EM_PPC, "PPC" },
	{ EM_PPC64, "PPC64" },
	{ EM_S390, "S390" },
	{ EM_V800, "V800" },
	{ EM_FR20, "FR20" },
	{ EM_RH32, "RH32" },
	{ EM_RCE, "RCE" },
	{ EM_ARM, "ARM" },
	{ EM_ALPHA, "ALPHA" },
	{ EM_SH, "SH" },
	{ EM_SPARCV9, "SPARCV9" },
	{ EM_TRICORE, "TRICORE" },
	{ EM_ARC, "ARC" },
	{ EM_H8_300, "H8_300" },
	{ EM_H8_300H, "H8_300H" },
	{ EM_H8S, "H8S" },
	{ EM_H8_500, "H8_500" },
	{ EM_IA_64, "IA_64" },
	{ EM_MIPS_X, "MIPS_X" },
	{ EM_COLDFIRE, "COLDFIRE" },
	{ EM_68HC12, "68HC12" },
	{ EM_MMA, "MMA" },
	{ EM_PCP, "PCP" },
	{ EM_NCPU, "NCPU" },
	{ EM_NDR1, "NDR1" },
	{ EM_STARCORE, "STARCORE" },
	{ EM_ME16, "ME16" },
	{ EM_ST100, "ST100" },
	{ EM_TINYJ, "TINYJ" },
	{ EM_X86_64, "X86_64" },
	{ EM_PDSP, "PDSP" },
	{ EM_PDP10, "PDP10" },
	{ EM_PDP11, "PDP11" },
	{ EM_FX66, "FX66" },
	{ EM_ST9PLUS, "ST9PLUS" },
	{ EM_ST7, "ST7" },
	{ EM_68HC16, "68HC16" },
	{ EM_68HC11, "68HC11" },
	{ EM_68HC08, "68HC08" },
	{ EM_68HC05, "68HC05" },
	{ EM_SVX, "SVX" },
	{ EM_ST19, "ST19" },
	{ EM_VAX, "VAX" },
	{ EM_CRIS, "CRIS" },
	{ EM_JAVELIN, "JAVELIN" },
	{ EM_FIREPATH, "FIREPATH" },
	{ EM_ZSP, "ZSP" },
	{ EM_MMIX, "MMIX" },
	{ EM_HUANY, "HUANY" },
	{ EM_PRISM, "PRISM" },
	{ EM_AVR, "AVR" },
	{ EM_FR30, "FR30" },
	{ EM_D10V, "D10V" },
	{ EM_D30V, "D30V" },
	{ EM_V850, "V850" },
	{ EM_M32R, "M32R" },
	{ EM_MN10300, "MN10300" },
	{ EM_MN10200, "MN10200" },
	{ EM_PJ, "PJ" },
	{ EM_OR1K, "OR1K" },
	{ EM_OPENRISC, "OPENRISC" },
	{ EM_ARC_A5, "ARC_A5" },
	{ EM_XTENSA, "XTENSA" },
	{ EM_VIDEOCORE, "VIDEOCORE" },
	{ EM_TMM_GPP, "TMM_GPP" },
	{ EM_NS32K, "NS32K" },
	{ EM_TPC, "TPC" },
	{ EM_SNP1K, "SNP1K" },
	{ EM_ST200, "ST200" },
	{ EM_IP2K, "IP2K" },
	{ EM_MAX, "MAX" },
	{ EM_CR, "CR" },
	{ EM_F2MC16, "F2MC16" },
	{ EM_MSP430, "MSP430" },
	{ EM_BLACKFIN, "BLACKFIN" },
	{ EM_SE_C33, "SE_C33" },
	{ EM_SEP, "SEP" },
	{ EM_ARCA, "ARCA" },
	{ EM_UNICORE, "UNICORE" },
	{ EM_ALTERA_NIOS2, "ALTERA_NIOS2" },
	{ EM_AARCH64, "AARCH64" },
	{ EM_AVR32, "AVR32" },
	{ EM_TILE64, "TILE64" },
	{ EM_TILEPRO, "TILEPRO" },
	{ EM_MICROBLAZE, "MICROBLAZE" },
	{ EM_TILEGX, "TILEGX" },
	{ EM_Z80, "Z80" },
	{ EM_RISCV, "RISCV" },
	{ EM_ALPHA_EXP, "ALPHA_EXP" },
	{ 0, NULL }
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
 */
static int
init_ehdr_push(lua_State *L, struct udataElf *ud, int elf_arg)
{
	const char *ident, *class;
	lua_Integer type;	/* file type */
	lua_Integer machine;	/* machine type */
	lua_Integer version;	/* version number */
	lua_Integer entry;	/* entry point */
	lua_Integer phoff;	/* Program hdr offset */
	lua_Integer shoff;	/* Section hdr offset */
	lua_Integer flags;	/* Processor flags */
	lua_Integer ehsize;	/* sizeof ehdr */
	lua_Integer phentsize;	/* Program header entry size */
	lua_Integer phnum;	/* Number of program headers */
	lua_Integer shentsize;	/* Section header entry size */
	lua_Integer shnum;	/* Number of section headers */
	lua_Integer shstrndx;	/* String table index */
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

	if (ud->flags & EHDR64) {
		Elf64_Ehdr *h = ud->ehdr;

		class = "ELFCLASS64";
		ident = (const char *)h->e_ident;
		type = h->e_type;
		machine = h->e_machine;
		version = h->e_version;
		entry = h->e_entry;
		phoff = h->e_phoff;
		shoff = h->e_shoff;
		flags = h->e_flags;
		ehsize = h->e_ehsize;
		phentsize = h->e_phentsize;
		phnum = h->e_phnum;
		shentsize = h->e_shentsize;
		shnum = h->e_shnum;
		shstrndx = h->e_shstrndx;
	} else {
		Elf32_Ehdr *h = ud->ehdr;

		class = "ELFCLASS32";
		ident = (const char *)h->e_ident;
		type = h->e_type;
		machine = h->e_machine;
		version = h->e_version;
		entry = h->e_entry;
		phoff = h->e_phoff;
		shoff = h->e_shoff;
		flags = h->e_flags;
		ehsize = h->e_ehsize;
		phentsize = h->e_phentsize;
		phnum = h->e_phnum;
		shentsize = h->e_shentsize;
		shnum = h->e_shnum;
		shstrndx = h->e_shstrndx;
	}

	lua_createtable(L, 0, 15);

	lua_pushstring(L, class);
	lua_setfield(L, -2, "class");
	lua_pushlstring(L, ident, ELF_NIDENT);
	lua_setfield(L, -2, "ident");
	lua_pushinteger(L, version);
	lua_setfield(L, -2, "version");
	lua_pushinteger(L, entry);
	lua_setfield(L, -2, "entry");
	lua_pushinteger(L, phoff);
	lua_setfield(L, -2, "phoff");
	lua_pushinteger(L, shoff);
	lua_setfield(L, -2, "shoff");
	lua_pushinteger(L, flags);
	lua_setfield(L, -2, "flags");
	lua_pushinteger(L, ehsize);
	lua_setfield(L, -2, "ehsize");
	lua_pushinteger(L, phentsize);
	lua_setfield(L, -2, "phentsize");
	lua_pushinteger(L, phnum);
	lua_setfield(L, -2, "phnum");
	lua_pushinteger(L, shentsize);
	lua_setfield(L, -2, "shentsize");
	lua_pushinteger(L, shnum);
	lua_setfield(L, -2, "shnum");
	lua_pushinteger(L, shstrndx);
	lua_setfield(L, -2, "shstrndx");

	/* Push e_type. */
	lua_rawgetp(L, LUA_REGISTRYINDEX, et_constants);
	lua_rawgeti(L, -1, type);

	if (lua_isnil(L, -1)) {
		lua_pushinteger(L, type);
		lua_replace(L, -2);
	}

	lua_setfield(L, -3, "type");
	lua_pop(L, 1);

	/* Push e_machine. */
	lua_rawgetp(L, LUA_REGISTRYINDEX, em_constants);
	lua_rawgeti(L, -1, machine);

	if (lua_isnil(L, -1)) {
		lua_pushinteger(L, machine);
		lua_replace(L, -2);
	}

	lua_setfield(L, -3, "machine");	/* machine type */
	lua_pop(L, 1);

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

	lua_getuservalue(L, 1);
	lua_getfield(L, -1, "type");

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

	lua_getuservalue(L, 1);
	lua_getfield(L, -1, "machine");

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
register_index(lua_State *L, const luaL_Reg index[])
{

	lua_pushstring(L, "__index");
	lua_newtable(L);
	luaL_setfuncs(L, index, 0);
	lua_rawset(L, -3);
}

static void
push_constants(lua_State *L, const struct KV kv[])
{
	size_t i;

	lua_createtable(L, 0, 0);

	for (i = 0; kv[i].val != NULL; i++) {
		lua_pushstring(L, kv[i].val);
		lua_rawseti(L, -2, kv[i].key);
	}
}

static const luaL_Reg elftoolchain[] = {
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

static const luaL_Reg elf_mt[] = {
	{ "__gc", l_elf_gc },
	{ "__tostring", l_elf_tostring },
	{ NULL, NULL }
};

static const luaL_Reg elf_index[] = {
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

static const luaL_Reg elf_scn_mt[] = {
	{ "__tostring", l_elf_scn_tostring },
	{ NULL, NULL }
};

static const luaL_Reg elf_scn_index[] = {
	{ "next", l_elf_scn_next },
	{ NULL, NULL }
};

int
luaopen_elftoolchain(lua_State *L)
{
	if (elf_version(EV_CURRENT) == EV_NONE)
		return luaL_error(L, "ELF library is too old");

	push_constants(L, et_constants);
	lua_rawsetp(L, LUA_REGISTRYINDEX, &et_constants);

	push_constants(L, em_constants);
	lua_rawsetp(L, LUA_REGISTRYINDEX, &em_constants);

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
