
-- Inspired by https://github.com/mike1k/VMPImportFixer

local unicorn = require 'unicorn'
local ucc = require 'unicorn.unicorn_const'
local x86 = require 'unicorn.x86_const'

local mod = {}

mod.parser = [[
vmpimpfix                               VMP Import Fix
    <module>   (optional string)

    -s, --section (default '.vmp0')     vmp section name
]]

function mod.main(args, out)
    require 'udbg.search'

    local target = assert(udbg.target)
    local m = args.module and target:get_module(args.module) or target.image
    local pe = require 'pefile'.FromAddress(m.base)
    local sec = pe.SectionList['.text']
    local vmpSec = pe.SectionList[args.section]
    local textCode = target:read_bytes(sec.Address, sec.VirtualSize)
    local vmpCode = target:read_bytes(vmpSec.Address, vmpSec.VirtualSize)

    local SP = x86.UC_X86_REG_RSP
    local P = 'I8'
    local MODE = ucc.UC_MODE_64
    if udbg.target 'wow64' then
        SP = x86.UC_X86_REG_ESP
        P = 'I4'
        MODE = ucc.UC_MODE_32
    end

    local function align(val, n) return (val + n - 1) & ~(n - 1) end
    local mu = unicorn.open(ucc.UC_ARCH_X86, MODE)
    mu:mem_map(sec.Address, align(sec.VirtualSize, 0x1000) + 0x1000)
    mu:mem_write(sec.Address, textCode)

    local mappedVmpSize = align(vmpSec.VirtualSize, 0x1000) + 0x1000
    mu:mem_map(vmpSec.Address, mappedVmpSize)
    mu:mem_write(vmpSec.Address, vmpCode)

    mu:reg_write(SP, vmpSec.Address + (mappedVmpSize - 0x1000) & -0x10)

    local targetProc
    mu:hook_add(ucc.UC_HOOK_CODE, function(uc, addr, size)
        local insn = mu:mem_read(addr, size)
        -- log('[insn]', hex(addr), insn:tohex())
        local b = insn:byte()
        if b == 0xC2 or b == 0xC3 then
            local sp = uc:reg_read(SP)
            targetProc = P:unpack(uc:mem_read(sp, 8))
            uc:emu_stop()
        end
    end, 1, 0)

    local callToVmp = table {}
    for a in target:find_binary {sec.Address, size = sec.VirtualSize, pattern = 'E8 ?? ?? ?? ??'} do
        local dis = target:disasm(a)
        local op, a1 = dis('operand', 0)
        local offset = a1 - vmpSec.Address
        if offset >= 0 and offset < vmpSec.VirtualSize and vmpCode:byte(offset+1) == 0x90 then
            log.info('Found call to %s in .text @ %X (call to %X)' % {args.section, a, a1})
            callToVmp:insert {from = a, to = a1}
        end
    end

    if #callToVmp == 0 then
        return ui.error('Unable to find any call/jmp sequences in the .text section!')
    end

    for _, item in ipairs(callToVmp) do
        local rsp = mu:reg_read(SP)
        mu:mem_write(rsp, P:pack(item.from + 5))
        targetProc = nil
        -- emulate code in infinite time & unlimited instructions
        local ok, err = pcall(mu.emu_start, mu, item.to, 0, 0, 30)
        if ok then
            out('call@', hex(item.from), '->', targetProc and target:get_symbol(targetProc) or '<FAILED>')
        else
            ui.error('call@', hex(item.from), err)
        end
    end
end

return mod