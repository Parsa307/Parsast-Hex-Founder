local gg = gg
function GetResults()
    gg.clearResults()
    gg.setVisible(false)
    Lib_start_address = gg.getRangesList('*.so')
    LibChoose = {}
    LibIndex = 1
    for i, v in ipairs(Lib_start_address) do
        if v.state == "Cd" then
            local result = v.name:match(".+/(.+)")
            if (result ~= "libil2cpp.so") and (result ~= "libunity.so") and (result ~= "libcrashlytics.so") and (result ~= "libmain.so") then
                LibChoose[LibIndex] = result
                LibIndex = LibIndex + 1
            end
        end
    end
    Chosen = gg.choice(LibChoose, "Choose the lib of mod menu")
    if not Chosen then return end  -- Exit if no choice was made

    Lib_start_address = gg.getRangesList(LibChoose[Chosen])
    GetCB = {}
    CBIndex = 1
    for i, v in ipairs(Lib_start_address) do
        if v.state == "Cd" then
            while v.start <= v['end'] do
                GetCB[CBIndex] = { address = v.start, flags = gg.TYPE_DWORD }
                CBIndex = CBIndex + 1
                v.start = v.start + 0x4
            end
        end
    end
    gg.setRanges(gg.REGION_C_DATA | gg.REGION_CODE_APP)
    gg.loadResults(GetCB)
    GetPointers = gg.getResults(gg.getResultsCount(), nil, nil, nil, nil, nil, nil, nil, gg.POINTER_EXECUTABLE_WRITABLE | gg.POINTER_EXECUTABLE | gg.POINTER_WRITABLE)

    gg.clearResults()
    for i, v in ipairs(GetPointers) do
        v.address = v.value
    end
    GetPointers = gg.getValues(GetPointers)
    
    KeepChecking(GetPointers)
end

function KeepChecking(refinedResults)
    local valuesToDetect = refinedResults
    gg.setVisible(false)
    while gg.isVisible() == false do
        gg.toast("Detecting Values")
        local valuesToDetectSecond = gg.getValues(valuesToDetect)
        local wasDifferent = false
        local changedValues = ""
        local changedValuesList = {}
        local changeCounter = 1

        for i, v in ipairs(valuesToDetect) do
            if valuesToDetect[i].value ~= valuesToDetectSecond[i].value then
                changedValuesList[changeCounter] = {
                    address = valuesToDetect[i].address,
                    flags = valuesToDetect[i].flags,
                    newHex = valuesToDetectSecond[i].value
                }
                changeCounter = changeCounter + 1
                wasDifferent = true
            end
        end

        if wasDifferent then
            changedValues = "Some values were detected\n\n"
            gg.loadResults(changedValuesList)

            local gettedValue = GetAddress(checkAndReturn())
            for i, v in ipairs(gettedValue) do
                if not changedValuesList[i].newHex then
                    changedValuesList[i].newHex = 111111
                end
                local HexValue1 = string.format("%X", changedValuesList[i].newHex)
                HexValue1 = littleEndianToBigEndian(HexValue1)
                HexValue1 = HexValue1:gsub('(..)', '%1 ')
                changedValues = changedValues .. "Offset: " .. gettedValue[i].offset .. "\nNew Hex: " .. HexValue1 .. "\n\n"
            end
            valuesToDetect = valuesToDetectSecond
            local choose = gg.alert(changedValues, "Continue", "Save", "Exit")

            if choose == 2 then
                gg.copyText(changedValues, false)
                gg.addListItems(changedValuesList)
            end

            if choose == 3 then
                gg.clearResults()
                gg.setVisible(true)
                os.exit()
            end
        end
    end
    os.exit()
end

function littleEndianToBigEndian(hexString)
    local chunks = {}

    for i = #hexString, 1, -2 do
        table.insert(chunks, string.sub(hexString, i-1, i))
    end
    
    return table.concat(chunks)
end

function UserMenu()
    firstMenu = gg.choice({"Real Time Show", "Exit"}, nil, "Script Made By Parsast")
    if firstMenu == nil then return end  -- Exit if no choice was made
    if firstMenu == 1 then
        GetResults()
    elseif firstMenu == 2 then
        os.exit()
    end
end

function GetAddress(valueTable)
    gg.clearResults()
    FinalOutputSchema = {}
    for i, v in ipairs(valueTable) do
        FinalOutputSchema[i] = {
            lib = v.lib,
            offset = v.offset,
            address = gg.getRangesList(v.lib)[1].start + v.offset,
            flags = gg.TYPE_DWORD
        }
    end
    return FinalOutputSchema
end

function getShortName(str)
    local a = str:gsub('.+/', '')
    if a:find(':') then a = a:gsub(':.+', '') end
    return a
end

function getLibAndBase(var)
    local name, base = {}, {}
    for i, v in ipairs(var) do
        if v.type:sub(3, 3) == 'x' then
            local a = { { address = v.start, flags = 4 } }
            local a = gg.getValues(a)
            if a[1].value == 0x464C457F then
                table.insert(name, getShortName(v.internalName))
                table.insert(base, v.start)
            end
        end
    end
    return name, base
end

function checkAndReturn()
    local res = gg.getResults(gg.getResultsCount())
    local pk = gg.getTargetInfo().packageName
    local lib = gg.getRangesList('/data/*' .. pk .. '*.so')

    local name, base = getLibAndBase(lib)
    local t = {}
    for i, v in ipairs(res) do
        for a, b in ipairs(lib) do
            if v.address >= b.start and v.address < b['end'] then
                for c, d in ipairs(name) do
                    local sn = getShortName(b.internalName)
                    if sn == d then
                        v.lib = d
                        v.offset = '0x' .. string.format('%x', v.address - base[c])
                        table.insert(t, v)
                    end
                end
            end
        end
    end
    return t
end

UserMenu()
