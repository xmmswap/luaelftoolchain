/*
 * MIT License
 *
 * Copyright (c) 2018 XMM SWAP LTD
 */

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>

#include <fcntl.h>
#include <unistd.h>

#include <lua.h>
#include <lauxlib.h>

#include <libelf.h>
#include <gelf.h>

#define ELF_MT "elftoolchain::Elf"
#define ELF_EHDR_MT "elftoolchain::GElf_Ehdr"
#define ELF_SCN_MT "elftoolchain::Elf_Scn"
#define ELF_ARSYM_MT "elftoolchain::Elf_Arsym"

struct udataElf {
	Elf *elf;
	void *mem; /* XXX implement */
	int fd;
};

struct udataElfScn {
	Elf_Scn *scn;
	void *shdr; /* Cached Elf32_Shdr or Elf64_Shdr object. */
	int flags;
#define SHDR64 1
};

struct KV {
	lua_Integer key;
	const char *val;
};

/*
 * See also l_elf_ehdr_index.
 */
static const char *ehdr_fields[] = {
	"type",
	"class",
	"entry",
	"flags",
	"ident",
	"phnum",
	"phoff",
	"shnum",
	"shoff",
	"ehsize",
	"machine",
	"version",
	"shstrndx",
	"phentsize",
	"shentsize",
	NULL
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

/* sh_type values. */
static const struct KV sht_constants[] = {
	{ SHT_NULL, "NULL" },
	{ SHT_PROGBITS, "PROGBITS" },
	{ SHT_SYMTAB, "SYMTAB" },
	{ SHT_STRTAB, "STRTAB" },
	{ SHT_RELA, "RELA" },
	{ SHT_HASH, "HASH" },
	{ SHT_DYNAMIC, "DYNAMIC" },
	{ SHT_NOTE, "NOTE" },
	{ SHT_NOBITS, "NOBITS" },
	{ SHT_REL, "REL" },
	{ SHT_SHLIB, "SHLIB" },
	{ SHT_DYNSYM, "DYNSYM" },
	{ SHT_INIT_ARRAY, "INIT_ARRAY" },
	{ SHT_FINI_ARRAY, "FINI_ARRAY" },
	{ SHT_PREINIT_ARRAY, "PREINIT_ARRAY" },
	{ SHT_GROUP, "GROUP" },
	{ SHT_SYMTAB_SHNDX, "SYMTAB_SHNDX" },
};

static int
l_next_field(lua_State *L)
{

	/* Make sure there is a slot for lua_next() to pop. */
	lua_settop(L, 2);

	if (lua_next(L, 1) == 0)
		return 0;

	lua_pop(L, 1);
	return 1;
}

/*
 * [-0, +2-1, -]
 * Push a string constant if key is found in constants, push key otherwise.
 */
static void
push_constant(lua_State *L, lua_Integer key, const struct KV constants[])
{
	int newtop;

	newtop = lua_gettop(L) + 1;

	lua_rawgetp(L, LUA_REGISTRYINDEX, constants);
	lua_rawgeti(L, -1, key);

	if (lua_isnil(L, -1))
		lua_pushinteger(L, key);

	lua_replace(L, newtop);
	lua_settop(L, newtop);
}

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

static struct udataElfScn *
test_elf_scn_udata(lua_State *L, int arg)
{

	return (struct udataElfScn *)luaL_testudata(L, arg, ELF_SCN_MT);
}

static struct udataElfScn *
check_elf_scn_udata(lua_State *L, int arg)
{

	return (struct udataElfScn *)luaL_checkudata(L, arg, ELF_SCN_MT);
}

static GElf_Ehdr *
push_gelf_ehdr_udata(lua_State *L)
{
	GElf_Ehdr *ud;

	ud = lua_newuserdata(L, sizeof(*ud));
	memset(ud, 0, sizeof(*ud));

	luaL_getmetatable(L, ELF_EHDR_MT);
	lua_setmetatable(L, -2);

	return ud;
}

static GElf_Ehdr *
check_gelf_ehdr_udata(lua_State *L, int arg)
{

	return (GElf_Ehdr *)luaL_checkudata(L, arg, ELF_EHDR_MT);
}

static int
push_err_results(lua_State *L, int err, const char *errmsg)
{

	if (errmsg == NULL)
		errmsg = elf_errmsg(err);

	lua_pushnil(L);
	lua_pushstring(L, errmsg);
	lua_pushinteger(L, err); /* XXX Convert to a string. */
	return 3;
}

static int
l_elf_begin(lua_State *L)
{
	struct udataElf *ud;
	const char *filename;

	filename = luaL_checkstring(L, 1);

	ud = (struct udataElf *)lua_newuserdata(L, sizeof(*ud));
	ud->elf = NULL;
	ud->mem = NULL;

	luaL_getmetatable(L, ELF_MT);
	lua_setmetatable(L, -2);

	if ((ud->fd = open(filename, O_RDONLY | O_CLOEXEC)) == -1) {
		int err = errno;

		/* XXX This function is not for reporting C errors. */
		return push_err_results(L, err, (const char *)strerror(err));
	}

	if ((ud->elf = elf_begin(ud->fd, ELF_C_READ, NULL)) == NULL)
		return push_err_results(L, elf_errno(), NULL);

	return 1;
}

static int
l_elf_getehdr(lua_State *L)
{
	struct udataElf *ud;
	GElf_Ehdr *ehdr;

	ud = check_elf_udata(L, 1, 1);
	ehdr = push_gelf_ehdr_udata(L);

	if (gelf_getehdr(ud->elf, ehdr) == NULL)
		return push_err_results(L, elf_errno(), NULL);

	return 1;
}

/*
 * Return an iterator over GElf_Ehdr fields.
 */
static int
l_elf_ehdr_fields(lua_State *L)
{

	lua_pushcfunction(L, &l_next_field);
	lua_rawgetp(L, LUA_REGISTRYINDEX, ehdr_fields);
	return 2;
}

/* XXX Implement l_elf_ehdr_newindex. */
static int
l_elf_ehdr_index(lua_State *L)
{
	GElf_Ehdr *ehdr;
	const char *key;
	size_t len;
	lua_Integer val;
	bool found = false;

	ehdr = check_gelf_ehdr_udata(L, 1);
	key = luaL_checklstring(L, 2, &len);

	/*
	 * XXX Extract EI_DATA EI_VERSION EI_OSABI EI_ABIVERSION from e_ident.
	 */
	switch (len) {
	case 4:
		/* type - file type */
		if (strcmp(key, "type") != 0)
			break;

		push_constant(L, ehdr->e_type, et_constants);
		return 1;
	case 5:
		/* class - ELFCLASS32 or ELFCLASS64 */
		/* entry - entry point */
		/* flags - Processor flags */
		/* ident - Id bytes */
		/* phnum - Number of program headers */
		/* phoff - Program hdr offset */
		/* shnum - Section header entry size */
		/* shoff - Section hdr offset */
		switch (key[0]) {
			bool isnum;
		case 'c':
			if (strcmp(key, "class") != 0)
				break;

			switch (ehdr->e_ident[EI_CLASS]) {
			case ELFCLASSNONE:
				lua_pushstring(L, "ELFCLASSNONE");
				return 1;
			case ELFCLASS32:
				lua_pushstring(L, "ELFCLASS32");
				return 1;
			case ELFCLASS64:
				lua_pushstring(L, "ELFCLASS64");
				return 1;
			default:
				found = false;
				break;
			}

			break;
		case 'e':
			found = !strcmp(key, "entry");
			val = ehdr->e_entry;
			break;
		case 'f':
			found = !strcmp(key, "flags");
			val = ehdr->e_flags;
			break;
		case 'i':
			if (strcmp(key, "ident") != 0)
				break;

			lua_pushlstring(L,
			    (const char *)ehdr->e_ident, ELF_NIDENT);
			return 1;
		case 'p':
			isnum = key[2] == 'n';
			found = !strcmp(key, isnum ? "phnum" : "phoff");
			val = isnum ? ehdr->e_phnum : ehdr->e_phoff;
			break;
		case 's':
			isnum = key[2] == 'n';
			found = !strcmp(key, isnum ? "shnum" : "shoff");
			val = isnum ? ehdr->e_shnum : ehdr->e_shoff;
			break;
		}
		break;
	case 6:
		/* ehsize - sizeof ehdr */
		/* fields - return an iterator */
		switch (key[0]) {
		case 'e':
			found = !strcmp(key, "ehsize");
			val = ehdr->e_ehsize;
			break;
		case 'f':
			if (strcmp(key, "fields") != 0)
				break;

			lua_pushcfunction(L, l_elf_ehdr_fields);
			return 1;
		}

		break;
	case 7:
		/* machine - machine type */
		/* version - version number */
		switch (key[0]) {
		case 'm':
			if (strcmp(key, "machine") != 0)
				break;

			push_constant(L, ehdr->e_machine, em_constants);
			return 1;
		case 'v':
			found = !strcmp(key, "version");
			val = ehdr->e_version;
			break;
		}
		break;
	case 8:
		/* shstrndx - String table index */
		found = !strcmp(key, "shstrndx");
		val = ehdr->e_shstrndx;
		break;
	case 9:
		/* phentsize - Program header entry size */
		/* shentsize - Section header entry size */
		switch (key[0]) {
		case 'p':
			found = !strcmp(key, "phentsize");
			val = ehdr->e_phentsize;
			break;
		case 's':
			found = !strcmp(key, "shentsize");
			val = ehdr->e_shentsize;
			break;
		}
		break;
	}

	if (!found)
		return 0;

	lua_pushinteger(L, val);
	return 1;
}

static int
l_elf_getshdrnum(lua_State *L)
{
	struct udataElf *ud;
	size_t shnum;

	ud = check_elf_udata(L, 1, 1);

	if (elf_getshdrnum(ud->elf, &shnum) != 0)
		return push_err_results(L, elf_errno(), NULL);

	lua_pushinteger(L, shnum);
	return 1;
}

static int
l_elf_getphdrnum(lua_State *L)
{
	struct udataElf *ud;
	size_t phnum;

	ud = check_elf_udata(L, 1, 1);

	if (elf_getphdrnum(ud->elf, &phnum) != 0)
		return push_err_results(L, elf_errno(), NULL);

	lua_pushinteger(L, phnum);
	return 1;
}

static int
l_elf_getshstrndx(lua_State *L)
{
	struct udataElf *ud;
	size_t ndx;

	ud = check_elf_udata(L, 1, 1);

	/*
	 * Unlike elf_getshdrnum(3) and elf_getphdrnum(3),
	 * elf_getshstrndx(3) returns 0 in case of an error.
	 */
	if (elf_getshstrndx(ud->elf, &ndx) == 0)
		return push_err_results(L, elf_errno(), NULL);

	lua_pushinteger(L, ndx);
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
	struct udataElfScn *ud;

	/* XXX Documentation isn't clear about how to detect an error. */
	scn = elf_nextscn(elf, scn);

	if (scn == NULL) {
		lua_pushnil(L);
		return 1;
	}

	ud = (struct udataElfScn *)lua_newuserdata(L, sizeof(*ud));
	ud->scn = NULL;
	ud->shdr = NULL;
	ud->flags = 0;

	luaL_getmetatable(L, ELF_SCN_MT);
	lua_setmetatable(L, -2);

	/* Keep a reference to the parent Elf object. */
	assert(luaL_testudata(L, elf_arg, ELF_MT) != NULL);
	lua_pushvalue(L, elf_arg);
	lua_setuservalue(L, -2);

	ud->scn = scn;

	return 1;
}

static int
l_elf_nextscn(lua_State *L)
{
	struct udataElf *elf;
	struct udataElfScn *ud;
	Elf_Scn *scn;

	elf = check_elf_udata(L, 1, 1);
	ud = test_elf_scn_udata(L, 2);
	scn = ud ? ud->scn : NULL;

	if (ud != NULL) {
		lua_getuservalue(L, 2);
		if (lua_touserdata(L, -1) != elf)
			return luaL_argerror(L, 2, "different parent");
	}

	return nextscn_push(L, elf->elf, scn, 1);
}

/*
 * Return an iterator over Elf_Scn objects.
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
	Elf_Scn *scn;
	struct udataElf *elf;
	struct udataElfScn *ud;

	ud = check_elf_scn_udata(L, 1);
	scn = ud->scn;

	lua_getuservalue(L, 1);
	elf = check_elf_udata(L, -1, 1);

	return nextscn_push(L, elf->elf, scn, lua_gettop(L));
}

static int
check_elf_scn_udata_load_shdr(lua_State *L, int arg, struct udataElfScn **p)
{
	struct udataElfScn *ud;
	int err;

	ud = check_elf_scn_udata(L, arg);
	*p = ud;

	if (ud->shdr == NULL)
		ud->shdr = elf32_getshdr(ud->scn);

	if (ud->shdr != NULL)
		return ELF_E_NONE;

	err = elf_errno();
	if (err != ELF_E_CLASS)
		return err;

	ud->shdr = elf64_getshdr(ud->scn);
	if (ud->shdr == NULL)
		return elf_errno();

	ud->flags |= SHDR64;

	return ELF_E_NONE;
}

static int
l_elf_scn_getshdr(lua_State *L)
{
	struct udataElfScn *ud;
	lua_Integer name;	/* section name (.shstrtab index) */
	lua_Integer type;	/* section type */
	lua_Integer flags;	/* section flags */
	lua_Integer addr;	/* virtual address */
	lua_Integer offset;	/* file offset */
	lua_Integer size;	/* section size */
	lua_Integer link;	/* link to another */
	lua_Integer info;	/* misc info */
	lua_Integer addralign;	/* memory alignment */
	lua_Integer entsize;	/* table entry size */
	int err;

	if ((err = check_elf_scn_udata_load_shdr(L, 1, &ud)) != ELF_E_NONE)
		return push_err_results(L, err, NULL);

	if (ud->flags & SHDR64) {
		Elf64_Shdr *h = ud->shdr;

		name = h->sh_name;
		type = h->sh_type;
		flags = h->sh_flags;
		addr = h->sh_addr;
		offset = h->sh_offset;
		size = h->sh_size;
		link = h->sh_link;
		info = h->sh_info;
		addralign = h->sh_addralign;
		entsize = h->sh_entsize;
	} else {
		Elf32_Shdr *h = ud->shdr;

		name = h->sh_name;
		type = h->sh_type;
		flags = h->sh_flags;
		addr = h->sh_addr;
		offset = h->sh_offset;
		size = h->sh_size;
		link = h->sh_link;
		info = h->sh_info;
		addralign = h->sh_addralign;
		entsize = h->sh_entsize;
	}

	lua_createtable(L, 0, 0);

	lua_pushinteger(L, name);
	lua_setfield(L, -2, "name");
	lua_pushinteger(L, flags);
	lua_setfield(L, -2, "flags");
	lua_pushinteger(L, addr);
	lua_setfield(L, -2, "addr");
	lua_pushinteger(L, offset);
	lua_setfield(L, -2, "offset");
	lua_pushinteger(L, size);
	lua_setfield(L, -2, "size");
	lua_pushinteger(L, link);
	lua_setfield(L, -2, "link");
	lua_pushinteger(L, info);
	lua_setfield(L, -2, "info");
	lua_pushinteger(L, addralign);
	lua_setfield(L, -2, "addralign");
	lua_pushinteger(L, entsize);
	lua_setfield(L, -2, "entsize");
	push_constant(L, type, sht_constants);
	lua_setfield(L, -3, "type");

	return 1;
}

static int
l_elf_scn_name(lua_State *L)
{
	struct udataElfScn *ud;
	lua_Integer name;
	int err;

	if ((err = check_elf_scn_udata_load_shdr(L, 1, &ud)) != ELF_E_NONE)
		return push_err_results(L, err, NULL);

	if (ud->flags & SHDR64) {
		Elf64_Shdr *h = ud->shdr;

		name = h->sh_name;
	} else {
		Elf32_Shdr *h = ud->shdr;

		name = h->sh_name;
	}

	lua_pushinteger(L, name);
	return 1;
}

static int
l_elf_scn_type(lua_State *L)
{
	struct udataElfScn *ud;
	lua_Integer type;
	int err;

	if ((err = check_elf_scn_udata_load_shdr(L, 1, &ud)) != ELF_E_NONE)
		return push_err_results(L, err, NULL);

	if (ud->flags & SHDR64) {
		Elf64_Shdr *h = ud->shdr;

		type = h->sh_type;
	} else {
		Elf32_Shdr *h = ud->shdr;

		type = h->sh_type;
	}

	push_constant(L, type, sht_constants);
	return 1;
}

static int
l_elf_scn_flags(lua_State *L)
{
	struct udataElfScn *ud;
	lua_Integer flags;
	int err;

	if ((err = check_elf_scn_udata_load_shdr(L, 1, &ud)) != ELF_E_NONE)
		return push_err_results(L, err, NULL);

	if (ud->flags & SHDR64) {
		Elf64_Shdr *h = ud->shdr;

		flags = h->sh_flags;
	} else {
		Elf32_Shdr *h = ud->shdr;

		flags = h->sh_flags;
	}

	lua_pushinteger(L, flags);
	return 1;
}

static int
l_elf_scn_addr(lua_State *L)
{
	struct udataElfScn *ud;
	lua_Integer addr;
	int err;

	if ((err = check_elf_scn_udata_load_shdr(L, 1, &ud)) != ELF_E_NONE)
		return push_err_results(L, err, NULL);

	if (ud->flags & SHDR64) {
		Elf64_Shdr *h = ud->shdr;

		addr = h->sh_addr;
	} else {
		Elf32_Shdr *h = ud->shdr;

		addr = h->sh_addr;
	}

	lua_pushinteger(L, addr);
	return 1;
}

static int
l_elf_scn_offset(lua_State *L)
{
	struct udataElfScn *ud;
	lua_Integer offset;
	int err;

	if ((err = check_elf_scn_udata_load_shdr(L, 1, &ud)) != ELF_E_NONE)
		return push_err_results(L, err, NULL);

	if (ud->flags & SHDR64) {
		Elf64_Shdr *h = ud->shdr;

		offset = h->sh_offset;
	} else {
		Elf32_Shdr *h = ud->shdr;

		offset = h->sh_offset;
	}

	lua_pushinteger(L, offset);
	return 1;
}

static int
l_elf_scn_size(lua_State *L)
{
	struct udataElfScn *ud;
	lua_Integer size;
	int err;

	if ((err = check_elf_scn_udata_load_shdr(L, 1, &ud)) != ELF_E_NONE)
		return push_err_results(L, err, NULL);

	if (ud->flags & SHDR64) {
		Elf64_Shdr *h = ud->shdr;

		size = h->sh_size;
	} else {
		Elf32_Shdr *h = ud->shdr;

		size = h->sh_size;
	}

	lua_pushinteger(L, size);
	return 1;
}

static int
l_elf_scn_link(lua_State *L)
{
	struct udataElfScn *ud;
	lua_Integer link;
	int err;

	if ((err = check_elf_scn_udata_load_shdr(L, 1, &ud)) != ELF_E_NONE)
		return push_err_results(L, err, NULL);

	if (ud->flags & SHDR64) {
		Elf64_Shdr *h = ud->shdr;

		link = h->sh_link;
	} else {
		Elf32_Shdr *h = ud->shdr;

		link = h->sh_link;
	}

	lua_pushinteger(L, link);
	return 1;
}

static int
l_elf_scn_info(lua_State *L)
{
	struct udataElfScn *ud;
	lua_Integer info;
	int err;

	if ((err = check_elf_scn_udata_load_shdr(L, 1, &ud)) != ELF_E_NONE)
		return push_err_results(L, err, NULL);

	if (ud->flags & SHDR64) {
		Elf64_Shdr *h = ud->shdr;

		info = h->sh_info;
	} else {
		Elf32_Shdr *h = ud->shdr;

		info = h->sh_info;
	}

	lua_pushinteger(L, info);
	return 1;
}

static int
l_elf_scn_addralign(lua_State *L)
{
	struct udataElfScn *ud;
	lua_Integer addralign;
	int err;

	if ((err = check_elf_scn_udata_load_shdr(L, 1, &ud)) != ELF_E_NONE)
		return push_err_results(L, err, NULL);

	if (ud->flags & SHDR64) {
		Elf64_Shdr *h = ud->shdr;

		addralign = h->sh_addralign;
	} else {
		Elf32_Shdr *h = ud->shdr;

		addralign = h->sh_addralign;
	}

	lua_pushinteger(L, addralign);
	return 1;
}

static int
l_elf_scn_entsize(lua_State *L)
{
	struct udataElfScn *ud;
	lua_Integer entsize;
	int err;

	if ((err = check_elf_scn_udata_load_shdr(L, 1, &ud)) != ELF_E_NONE)
		return push_err_results(L, err, NULL);

	if (ud->flags & SHDR64) {
		Elf64_Shdr *h = ud->shdr;

		entsize = h->sh_entsize;
	} else {
		Elf32_Shdr *h = ud->shdr;

		entsize = h->sh_entsize;
	}

	lua_pushinteger(L, entsize);
	return 1;
}

static int
l_elf_scn_tostring(lua_State *L)
{
	struct udataElfScn *ud;

	ud = test_elf_scn_udata(L, 1);
	assert(ud != NULL);

	lua_pushfstring(L, "Elf_Scn%s@%p", ud->scn ? "" : "(inactive)", ud);
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
push_fields(lua_State *L, const char *fields[])
{
	size_t i;

	lua_createtable(L, 0, 0);

	for (i = 0; fields[i] != NULL; i++) {
		lua_pushboolean(L, false);
		lua_setfield(L, -2, fields[i]);
	}
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
	{ "getshdrnum", l_elf_getshdrnum },
	{ "getphdrnum", l_elf_getphdrnum },
	{ "getshstrndx", l_elf_getshstrndx },
	{ "getshdr", l_elf_scn_getshdr },
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
	{ "getshdrnum", l_elf_getshdrnum },
	{ "getphdrnum", l_elf_getphdrnum },
	{ "getshstrndx", l_elf_getshstrndx },
	{ NULL, NULL }
};

static const luaL_Reg elf_scn_mt[] = {
	{ "__tostring", l_elf_scn_tostring },
	{ NULL, NULL }
};

static const luaL_Reg elf_scn_index[] = {
	{ "next", l_elf_scn_next },
	{ "getshdr", l_elf_scn_getshdr },
	{ "name", l_elf_scn_name },
	{ "type", l_elf_scn_type },
	{ "flags", l_elf_scn_flags },
	{ "addr", l_elf_scn_addr },
	{ "offset", l_elf_scn_offset },
	{ "size", l_elf_scn_size },
	{ "link", l_elf_scn_link },
	{ "info", l_elf_scn_info },
	{ "addralign", l_elf_scn_addralign },
	{ "entsize", l_elf_scn_entsize },
	{ NULL, NULL }
};

int
luaopen_elftoolchain(lua_State *L)
{
	if (elf_version(EV_CURRENT) == EV_NONE)
		return luaL_error(L, "ELF library is too old");

	push_fields(L, ehdr_fields);
	lua_rawsetp(L, LUA_REGISTRYINDEX, &ehdr_fields);

	push_constants(L, et_constants);
	lua_rawsetp(L, LUA_REGISTRYINDEX, &et_constants);

	push_constants(L, em_constants);
	lua_rawsetp(L, LUA_REGISTRYINDEX, &em_constants);

	push_constants(L, sht_constants);
	lua_rawsetp(L, LUA_REGISTRYINDEX, &sht_constants);

	luaL_newmetatable(L, ELF_MT);
	luaL_setfuncs(L, elf_mt, 0);
	register_index(L, elf_index);

	luaL_newmetatable(L, ELF_SCN_MT);
	luaL_setfuncs(L, elf_scn_mt, 0);
	register_index(L, elf_scn_index);

	luaL_newmetatable(L, ELF_EHDR_MT);
	lua_pushstring(L, "__index");
	lua_pushcfunction(L, l_elf_ehdr_index);
	lua_rawset(L, -3);

	luaL_newlibtable(L, elftoolchain);
	luaL_setfuncs(L, elftoolchain, 0);

	return 1;
}
