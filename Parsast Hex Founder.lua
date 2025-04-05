local gg = gg

-- Function to gather memory ranges for libraries and filter out unwanted ones
function GetResults()
    gg.clearResults()
    gg.setVisible(false)
    local Lib_start_address = gg.getRangesList('*.so')
    local LibChoose = {}
    local uniqueLibs = {}

    -- Filter libraries and present a choice to the user
    for _, v in ipairs(Lib_start_address) do
        if v.state == "Cd" then
            local result = v.name:match(".+/(.+)")
            if not (result == "libil2cpp.so" or result == "libunity.so" or result == "libcrashlytics.so" or result == "libcrashlytics-common.so" or result == "libmain.so") then
                if not uniqueLibs[result] then
                    uniqueLibs[result] = true
                    table.insert(LibChoose, result)
                end
            end
        end
    end

    -- Check if no suitable libraries are found
    if #LibChoose == 0 then
        gg.alert("No suitable libraries found.")
        return
    end

    local Chosen = gg.choice(LibChoose, "Choose the lib of the mod menu:")
    if not Chosen then return end

    local Lib_start_address = gg.getRangesList(LibChoose[Chosen])
    local GetCB = {}

    -- Iterate through memory addresses and collect data
    for _, v in ipairs(Lib_start_address) do
        if v.state == "Cd" then
            for addr = v.start, v['end'], 0x4 do
                table.insert(GetCB, { address = addr, flags = gg.TYPE_DWORD })
            end
        end
    end

    gg.setRanges(gg.REGION_C_DATA | gg.REGION_CODE_APP)
    gg.loadResults(GetCB)
    local GetPointers = gg.getResults(gg.getResultsCount(), nil, nil, nil, nil, nil, nil, nil, gg.POINTER_EXECUTABLE_WRITABLE | gg.POINTER_EXECUTABLE | gg.POINTER_WRITABLE)

    gg.clearResults()
    for _, v in ipairs(GetPointers) do
        v.address = v.value
    end
    KeepChecking(gg.getValues(GetPointers))
end

-- Function to monitor changes in memory values and handle detected changes
function KeepChecking(refinedResults)
    local valuesToDetect = refinedResults
    gg.setVisible(false)

    while not gg.isVisible() do
        gg.toast("Detecting values...")
        local valuesToDetectSecond = gg.getValues(valuesToDetect)
        local changedValuesList = {}

        -- Check for changes in detected memory values
        for i, v in ipairs(valuesToDetect) do
            if v.value ~= valuesToDetectSecond[i].value then
                table.insert(changedValuesList, {
                    address = v.address,
                    flags = v.flags,
                    newHex = valuesToDetectSecond[i].value
                })
            end
        end

        -- If changes are detected, process them
        if #changedValuesList > 0 then
            local changedValues = "Some values were detected!\n"
            gg.loadResults(changedValuesList)
            local gettedValue = GetAddress(checkAndReturn())

            -- Format and display the changed values
            for i, v in ipairs(gettedValue) do
                local HexValue1 = string.format("%08X", changedValuesList[i].newHex or 0x111111)
                HexValue1 = littleEndianToBigEndian(HexValue1):sub(9):gsub('(..)', '%1 '):gsub('%s$', '')
                local Offset = "0x" .. string.upper(v.offset:sub(3))
                if i > 1 then
                    changedValues = changedValues .. "\n\n"
                end
                changedValues = changedValues .. string.format("Offset: %s\nHex: %s", Offset, HexValue1)
            end

            -- Allow the user to choose what to do with the results
            local choose = gg.alert(changedValues, "Continue", "Copy", "Exit")
            if choose == 2 then 
                gg.copyText(changedValues, false)
                gg.clearResults()
            end
            if choose == 3 then 
                gg.clearResults() 
                gg.setVisible(true) 
                os.exit() 
            end
        end

        valuesToDetect = valuesToDetectSecond
    end
    os.exit()
end

-- Function to convert a hexadecimal value from little-endian to big-endian
function littleEndianToBigEndian(hexString)
    return hexString:gsub('(..)(..)(..)(..)', '%4%3%2%1')
end

-- Function to display the main menu and handle user input
function UserMenu()
    local firstMenu = gg.choice({"Real Time Detection", "Exit"}, "Main Menu")
    if firstMenu == 1 then
        GetResults()
    elseif firstMenu == 2 then
        os.exit()
    end
end

-- Function to calculate the base address and offsets of detected memory values
function GetAddress(valueTable)
    local FinalOutputSchema = {}
    for _, v in ipairs(valueTable) do
        local libStart = gg.getRangesList(v.lib)[1].start
        table.insert(FinalOutputSchema, {
            lib = v.lib,
            offset = "0x" .. string.upper(v.offset:sub(3)),
            address = libStart + v.offset,
            flags = gg.TYPE_DWORD
        })
    end
    return FinalOutputSchema
end

-- Function to extract the short name of a library from its full path
function getShortName(str)
    return str:match(".+/(.+)") or str
end

-- Function to retrieve library names and their base addresses
function getLibAndBase(var)
    local name, base = {}, {}
    for _, v in ipairs(var) do
        if v.type:sub(3, 3) == 'x' and gg.getValues({ { address = v.start, flags = 4 } })[1].value == 0x464C457F then
            table.insert(name, getShortName(v.internalName))
            table.insert(base, v.start)
        end
    end
    return name, base
end

-- Function to calculate the offsets of results relative to their library base
function checkAndReturn()
    local res = gg.getResults(gg.getResultsCount())
    local lib = gg.getRangesList('/data/*' .. gg.getTargetInfo().packageName .. '*.so')
    local name, base = getLibAndBase(lib)
    local t = {}

    for _, v in ipairs(res) do
        for i, b in ipairs(lib) do
            if v.address >= b.start and v.address < b['end'] then
                for j, d in ipairs(name) do
                    if getShortName(b.internalName) == d then
                        table.insert(t, { lib = d, offset = "0x" .. string.upper(string.format('%x', v.address - base[j])) })
                    end
                end
            end
        end
    end
    return t
end

UserMenu()
