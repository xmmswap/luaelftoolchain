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

#define MT_PREFIX "elftoolchain."
#define ELF_MT       MT_PREFIX "Elf"
#define ELF_SCN_MT   MT_PREFIX "Elf_Scn"
#define ELF_DATA_MT  MT_PREFIX "Elf_Data"

#define ELF_EHDR_MT  MT_PREFIX "GElf_Ehdr"
#define ELF_SHDR_MT  MT_PREFIX "GElf_Shdr"
#define ELF_SYM_MT   MT_PREFIX "GElf_Sym"

struct udataElf {
	Elf *elf;
	void *mem; /* XXX implement */
	int fd;
};

struct udataElfScn {
	Elf_Scn *scn;
};

struct udataElfData {
	Elf_Data *data;
	Elf_Scn *scn;
};

struct KV {
	lua_Integer key;
	const char *val;
};

/*
 * All public fields of GElf_Ehdr struct.
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

/*
 * All public fields of GElf_Shdr struct.
 */
static const char *shdr_fields[] = {
	"addr",
	"info",
	"link",
	"name",
	"size",
	"type",
	"flags",
	"offset",
	"entsize",
	"addralign",
	NULL
};

/*
 * All public fields of GElf_Sym struct.
 */
static const char *sym_fields[] = {
	"info",
	"name",
	"size",
	"other",
	"shndx",
	"value",
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

/* st_info values. */
static const struct KV stt_constants[] = {
	{ STT_NOTYPE, "NOTYPE" },
	{ STT_OBJECT, "OBJECT" },
	{ STT_FUNC, "FUNC" },
	{ STT_SECTION, "SECTION" },
	{ STT_FILE, "FILE" },
	{ STT_COMMON, "COMMON" },
	{ STT_TLS, "TLS" },
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

	if (lua_rawgeti(L, -1, key) == LUA_TNIL)
		lua_pushinteger(L, key);

	lua_replace(L, newtop);
	lua_settop(L, newtop);
}

static int
error_closed_elf(lua_State *L, int arg)
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

	ud = luaL_checkudata(L, arg, ELF_MT);
	if (ud->elf == NULL)
		error_closed_elf(L, err_arg);

	return ud;
}

static struct udataElfScn *
test_elf_scn_udata(lua_State *L, int arg)
{
	struct udataElfScn *ud;

	ud = luaL_testudata(L, arg, ELF_SCN_MT);
	assert(ud == NULL || ud->scn != NULL);
	return ud;
}

static struct udataElfScn *
check_elf_scn_udata(lua_State *L, int arg, int err_arg)
{
	struct udataElfScn *ud;

	ud = luaL_checkudata(L, arg, ELF_SCN_MT);
	assert(ud->scn != NULL);
	return ud;
}

static struct udataElfData *
test_elf_data_udata(lua_State *L, int arg)
{

	return luaL_testudata(L, arg, ELF_DATA_MT);
}

static struct udataElfData *
check_elf_data_udata(lua_State *L, int arg, bool push_uservalue)
{
	struct udataElfData *ud;

	ud = luaL_checkudata(L, arg, ELF_DATA_MT);
	if (ud == NULL)
		return ud;

	lua_getuservalue(L, arg);
	check_elf_udata(L, -1, -1);

	if (!push_uservalue)
		lua_pop(L, 1);

	return ud;
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

	return luaL_checkudata(L, arg, ELF_EHDR_MT);
}

static GElf_Shdr *
push_gelf_shdr_udata(lua_State *L)
{
	GElf_Shdr *ud;

	ud = lua_newuserdata(L, sizeof(*ud));
	memset(ud, 0, sizeof(*ud));

	luaL_getmetatable(L, ELF_SHDR_MT);
	lua_setmetatable(L, -2);

	return ud;
}

static GElf_Shdr *
check_gelf_shdr_udata(lua_State *L, int arg)
{

	return luaL_checkudata(L, arg, ELF_SHDR_MT);
}

static GElf_Sym *
push_gelf_sym_udata(lua_State *L)
{
	GElf_Sym *ud;

	ud = lua_newuserdata(L, sizeof(*ud));
	memset(ud, 0, sizeof(*ud));

	luaL_getmetatable(L, ELF_SYM_MT);
	lua_setmetatable(L, -2);

	return ud;
}

static GElf_Sym *
check_gelf_sym_udata(lua_State *L, int arg)
{

	return luaL_checkudata(L, arg, ELF_SYM_MT);
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

	ud = lua_newuserdata(L, sizeof(*ud));
	memset(ud, 0, sizeof(*ud));

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
l_gelf_ehdr_fields(lua_State *L)
{

	lua_pushcfunction(L, &l_next_field);
	lua_rawgetp(L, LUA_REGISTRYINDEX, ehdr_fields);
	return 2;
}

/*
 * Return an iterator over GElf_Shdr fields.
 */
static int
l_gelf_shdr_fields(lua_State *L)
{

	lua_pushcfunction(L, &l_next_field);
	lua_rawgetp(L, LUA_REGISTRYINDEX, shdr_fields);
	return 2;
}

/*
 * Return an iterator over GElf_Sym fields.
 */
static int
l_gelf_sym_fields(lua_State *L)
{

	lua_pushcfunction(L, &l_next_field);
	lua_rawgetp(L, LUA_REGISTRYINDEX, sym_fields);
	return 2;
}

static int
l_gelf_fields(lua_State *L)
{

	lua_pushvalue(L, lua_upvalueindex(1));

	if (lua_type(L, 1) == LUA_TUSERDATA)
		lua_getmetatable(L, 1);
	else
		lua_pushvalue(L, 1);

	if (lua_rawget(L, -2) == LUA_TNIL)
		return 0;

	lua_pushcfunction(L, &l_next_field);
	lua_pushvalue(L, -2);
	return 2;
}

/* XXX Implement l_gelf_ehdr_newindex. */
static int
l_gelf_ehdr_index(lua_State *L)
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

			lua_pushcfunction(L, l_gelf_ehdr_fields);
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

/* XXX Implement l_gelf_shdr_newindex. */
static int
l_gelf_shdr_index(lua_State *L)
{
	GElf_Shdr *shdr;
	const char *key;
	size_t len;
	lua_Integer val;
	bool found = false;

	shdr = check_gelf_shdr_udata(L, 1);
	key = luaL_checklstring(L, 2, &len);

	switch (len) {
	case 4:
		/* addr - virtual address */
		/* info - misc info */
		/* link - link to another */
		/* name - section name (.shstrtab index) */
		/* size - section size */
		/* type - section type */
		switch (key[0]) {
		case 'a':
			found = !strcmp(key, "addr");
			val = shdr->sh_addr;
			break;
		case 'i':
			found = !strcmp(key, "info");
			val = shdr->sh_info;
			break;
		case 'l':
			found = !strcmp(key, "link");
			val = shdr->sh_link;
			break;
		case 'n':
			found = !strcmp(key, "name");
			val = shdr->sh_name;
			break;
		case 's':
			found = !strcmp(key, "size");
			val = shdr->sh_size;
			break;
		case 't':
			if (strcmp(key, "type") != 0)
				break;

			push_constant(L, shdr->sh_type, sht_constants);
			return 1;
		}

		break;
	case 5:
		/* flags - section flags */
		found = !strcmp(key, "flags");
		val = shdr->sh_flags;
		break;
	case 6:
		/* fields - return an iterator */
		/* offset - file offset */
		switch (key[0]) {
		case 'f':
			if (strcmp(key, "fields") != 0)
				break;

			lua_pushcfunction(L, l_gelf_shdr_fields);
			return 1;
		case 'o':
			found = !strcmp(key, "offset");
			val = shdr->sh_offset;
			break;
		}

		break;
	case 7:
		/* entsize - table entry size */
		found = !strcmp(key, "entsize");
		val = shdr->sh_entsize;
		break;
	case 9:
		/* addralign - memory alignment */
		found = !strcmp(key, "addralign");
		val = shdr->sh_addralign;
		break;
	}

	if (!found)
		return 0;

	lua_pushinteger(L, val);
	return 1;
}

/* XXX Implement l_gelf_sym_newindex. */
static int
l_gelf_sym_index(lua_State *L)
{
	GElf_Sym *sym;
	const char *key;
	size_t len;
	lua_Integer val;
	bool found = false;

	sym = check_gelf_sym_udata(L, 1);
	key = luaL_checklstring(L, 2, &len);

	switch (len) {
	case 4:
		/* info - type / binding attrs */
		/* name - Symbol name (.strtab index) */
		/* size - size of symbol */
		switch (key[0]) {
		case 'i':
			if (strcmp(key, "info") != 0)
				break;

			push_constant(L, sym->st_info, stt_constants);
			return 1;
		case 'n':
			found = !strcmp(key, "name");
			val = sym->st_name;
			break;
		case 's':
			found = !strcmp(key, "size");
			val = sym->st_size;
			break;
		}

		break;
	case 5:
		/* other - unused */
		/* shndx - section index of symbol */
		/* value - value of symbol */
		switch (key[0]) {
		case 'o':
			found = !strcmp(key, "other");
			val = sym->st_other;
			break;
		case 's':
			found = !strcmp(key, "shndx");
			val = sym->st_shndx;
			break;
		case 'v':
			found = !strcmp(key, "value");
			val = sym->st_value;
			break;
		}

		break;
	case 6:
		/* fields - return an iterator */
		if (strcmp(key, "fields") != 0)
			break;

		lua_pushcfunction(L, l_gelf_sym_fields);
		return 1;
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

/* XXX Return userdata ? */
static int
l_elf_strptr(lua_State *L)
{
	struct udataElf *ud;
	lua_Integer scndx, stroffset;
	char *str;

	ud = check_elf_udata(L, 1, 1);

	/* XXX Accept userdata and access sh_link and st_name */
	scndx = luaL_checkinteger(L, 2);
	stroffset = luaL_checkinteger(L, 3);

	if ((str = elf_strptr(ud->elf, scndx, stroffset)) == NULL)
		return push_err_results(L, elf_errno(), NULL);

	lua_pushstring(L, str);
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

	ud = lua_newuserdata(L, sizeof(*ud));
	memset(ud, 0, sizeof(*ud));

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

	ud = check_elf_scn_udata(L, 1, 1);
	scn = ud->scn;

	lua_getuservalue(L, 1);
	elf = check_elf_udata(L, -1, 1);

	return nextscn_push(L, elf->elf, scn, lua_gettop(L));
}

static int
l_elf_scn_getshdr(lua_State *L)
{
	struct udataElfScn *ud;
	GElf_Shdr *shdr;

	ud = check_elf_scn_udata(L, 1, 1);
	shdr = push_gelf_shdr_udata(L);

	if (gelf_getshdr(ud->scn, shdr) == NULL)
		return push_err_results(L, elf_errno(), NULL);

	return 1;
}

/*
 * Call elf_getdata(3), wrap the returned object and push it to the L's stack.
 * The function expects parent Elf object at the top and it sets uservalue
 * of the pushed object to that parent Elf object.
 */
static int
getdata_push(lua_State *L, Elf_Scn *scn, Elf_Data *data)
{
	struct udataElfData *ud;

	data = elf_getdata(scn, data);

	if (data == NULL) {
		/* XXX Error handling. */
		lua_pushnil(L);
		return 1;
	}

	ud = lua_newuserdata(L, sizeof(*ud));
	memset(ud, 0, sizeof(*ud));

	luaL_getmetatable(L, ELF_DATA_MT);
	lua_setmetatable(L, -2);

	/* Keep a reference to the parent Elf object. */
	lua_pushvalue(L, -2);
	lua_setuservalue(L, -2);

	ud->data = data;
	ud->scn = scn;

	return 1;
}

static int
l_elf_scn_getdata(lua_State *L)
{
	struct udataElfScn *scn;
	struct udataElfData *ud;

	scn = check_elf_scn_udata(L, 1, 1);
	ud = test_elf_data_udata(L, 2);

	lua_getuservalue(L, 1);
	check_elf_udata(L, -1, -1);

	return getdata_push(L, scn->scn, ud ? ud->data : NULL);
}

static int
l_elf_data_next(lua_State *L)
{
	struct udataElfData *ud;

	ud = check_elf_data_udata(L, 1, true);

	return getdata_push(L, ud->scn, ud->data);
}


/*
 * Return an iterator over Elf_Data objects.
 */
static int
l_elf_scn_data(lua_State *L)
{

	lua_pushcfunction(L, &l_elf_scn_getdata);
	lua_pushvalue(L, 1);
	return 2;
}

static int
l_elf_data_getsym(lua_State *L)
{
	struct udataElfData *ud;
	GElf_Sym *sym;
	lua_Integer ndx;

	ud = check_elf_data_udata(L, 1, false);
	ndx = luaL_checkinteger(L, 2);
	sym = push_gelf_sym_udata(L);

	if (gelf_getsym(ud->data, ndx, sym) == NULL)
		return push_err_results(L, elf_errno(), NULL);

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

static int
l_elf_data_tostring(lua_State *L)
{
	struct udataElfData *ud;

	ud = test_elf_data_udata(L, 1);
	assert(ud != NULL);

	lua_pushfstring(L, "Elf_Data%s@%p", ud->data ? "" : "(inactive)", ud);
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
register_fields(lua_State *L, int reg, const char *mt, const char *fields[])
{
	size_t i;

	if (reg < 0)
		reg += lua_gettop(L) + 1;

	assert(reg > 0 && lua_type(L, reg) == LUA_TTABLE);
	assert(strchr(MT_PREFIX, '_') == NULL);

	luaL_getmetatable(L, mt); /* mtkey */
	lua_createtable(L, 0, 0); /* t */

	for (i = 0; fields[i] != NULL; i++) {
		lua_pushboolean(L, false);
		lua_setfield(L, -2, fields[i]);
	}

	lua_pushvalue(L, -1); /* t */
	lua_rawsetp(L, LUA_REGISTRYINDEX, fields);

	lua_pushvalue(L, -1); /* t */
	lua_setfield(L, reg, strchr(mt, '_') + 1);

	lua_rawset(L, reg); /* reg[mtkey] =  t */
}

static void
register_constants(lua_State *L, const struct KV kv[])
{
	size_t i;

	lua_createtable(L, 0, 0);

	for (i = 0; kv[i].val != NULL; i++) {
		lua_pushstring(L, kv[i].val);
		lua_rawseti(L, -2, kv[i].key);
	}

	lua_rawsetp(L, LUA_REGISTRYINDEX, kv);
}

static const luaL_Reg elftoolchain[] = {
	{ "begin", l_elf_begin },
	{ "elf_end", l_elf_gc },
	{ "nextscn", l_elf_nextscn },
	{ "getehdr", l_elf_getehdr },
	{ "getshdrnum", l_elf_getshdrnum },
	{ "getphdrnum", l_elf_getphdrnum },
	{ "getshstrndx", l_elf_getshstrndx },
	{ "strptr", l_elf_strptr },
	{ "getshdr", l_elf_scn_getshdr },
	{ "getdata", l_elf_scn_getdata },
	{ "getsym", l_elf_data_getsym },
	{ "fields", l_gelf_fields },
	{ NULL, NULL }
};

static const luaL_Reg elf_mt[] = {
	{ "__gc", l_elf_gc },
	{ "__tostring", l_elf_tostring },
	{ NULL, NULL }
};

static const luaL_Reg elf_index[] = {
	{ "close", l_elf_gc },
	{ "elf_end", l_elf_gc },
	{ "nextscn", l_elf_nextscn },
	{ "scn", l_elf_scn },
	{ "getehdr", l_elf_getehdr },
	{ "getshdrnum", l_elf_getshdrnum },
	{ "getphdrnum", l_elf_getphdrnum },
	{ "getshstrndx", l_elf_getshstrndx },
	{ "strptr", l_elf_strptr },
	{ NULL, NULL }
};

static const luaL_Reg elf_scn_mt[] = {
	{ "__tostring", l_elf_scn_tostring },
	{ NULL, NULL }
};

static const luaL_Reg elf_scn_index[] = {
	{ "next", l_elf_scn_next },
	{ "getshdr", l_elf_scn_getshdr },
	{ "getdata", l_elf_scn_getdata },
	{ "data", l_elf_scn_data },
	{ NULL, NULL }
};

static const luaL_Reg elf_data_mt[] = {
	{ "__tostring", l_elf_data_tostring },
	{ NULL, NULL }
};

static const luaL_Reg elf_data_index[] = {
	{ "next", l_elf_data_next },
	{ "getsym", l_elf_data_getsym },
	{ NULL, NULL }
};

int
luaopen_elftoolchain(lua_State *L)
{
	if (elf_version(EV_CURRENT) == EV_NONE)
		return luaL_error(L, "ELF library is too old");

	register_constants(L, et_constants);
	register_constants(L, em_constants);
	register_constants(L, sht_constants);
	register_constants(L, stt_constants);

	luaL_newmetatable(L, ELF_MT);
	luaL_setfuncs(L, elf_mt, 0);
	register_index(L, elf_index);

	luaL_newmetatable(L, ELF_SCN_MT);
	luaL_setfuncs(L, elf_scn_mt, 0);
	register_index(L, elf_scn_index);

	luaL_newmetatable(L, ELF_DATA_MT);
	luaL_setfuncs(L, elf_data_mt, 0);
	register_index(L, elf_data_index);

	luaL_newmetatable(L, ELF_EHDR_MT);
	lua_pushstring(L, "__index");
	lua_pushcfunction(L, l_gelf_ehdr_index);
	lua_rawset(L, -3);

	luaL_newmetatable(L, ELF_SHDR_MT);
	lua_pushstring(L, "__index");
	lua_pushcfunction(L, l_gelf_shdr_index);
	lua_rawset(L, -3);

	luaL_newmetatable(L, ELF_SYM_MT);
	lua_pushstring(L, "__index");
	lua_pushcfunction(L, l_gelf_sym_index);
	lua_rawset(L, -3);

	luaL_newlibtable(L, elftoolchain);

	lua_createtable(L, 0, 0); /* upvalue */
	register_fields(L, -1, ELF_EHDR_MT, ehdr_fields);
	register_fields(L, -1, ELF_SHDR_MT, shdr_fields);
	register_fields(L, -1, ELF_SYM_MT,  sym_fields);

	luaL_setfuncs(L, elftoolchain, 1);

	return 1;
}
