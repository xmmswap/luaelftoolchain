local elf = require "elftoolchain"

local ksyms = assert(elf.begin("/dev/ksyms"))

for scn in ksyms:sections("SYMTAB") do
	local hdr = scn:getshdr()
	if hdr.entsize > 0 then
		local size = hdr.size // hdr.entsize
		local data = scn:getdata()
		for i = 1, size do
			local sym = data:getsym(i-1)
			if sym.type == "FUNC" then
				print(sym.visibility, sym.bind,
				    ksyms:strptr(hdr, sym))
			end
		end
	end
end
