-- Read-only bloxguard bundle exporter for the selected Studio instance.
-- Review this file before running it. It reads properties and prints JSON.
-- It never calls scripts, requires modules, changes instances, or uses HTTP.

local CollectionService = game:GetService("CollectionService")
local HttpService = game:GetService("HttpService")
local Selection = game:GetService("Selection")

local MAX_INSTANCES = 600000
local MAX_SOURCE_BYTES = 2 * 1024 * 1024
local MAX_BUNDLE_BYTES = 8 * 1024 * 1024

local selected = Selection:Get()
assert(#selected == 1, "Select exactly one root instance before exporting")

local function readProperty(instance, propertyName)
	local ok, value = pcall(function()
		return instance[propertyName]
	end)
	if ok then
		return value
	end
	return nil
end

local function jsonValue(value)
	local kind = typeof(value)
	if kind == "string" or kind == "number" or kind == "boolean" then
		return value
	elseif kind == "EnumItem" or kind == "Instance" then
		return tostring(value)
	elseif kind == "Vector2" then
		return { type = "Vector2", x = value.X, y = value.Y }
	elseif kind == "Vector3" then
		return { type = "Vector3", x = value.X, y = value.Y, z = value.Z }
	elseif kind == "Color3" then
		return { type = "Color3", r = value.R, g = value.G, b = value.B }
	elseif kind == "BrickColor" then
		return { type = "BrickColor", name = value.Name, number = value.Number }
	elseif kind == "CFrame" then
		return { type = "CFrame", components = { value:GetComponents() } }
	elseif kind == "Content" then
		-- Only a URI can name content outside the place. Empty content is omitted.
		local ok, uri = pcall(function()
			return value.Uri
		end)
		if ok and typeof(uri) == "string" and uri ~= "" then
			return uri
		end
		return nil
	end
	return { type = kind, value = tostring(value) }
end

local function readAttributes(instance)
	local result = {}
	for name, value in pairs(instance:GetAttributes()) do
		result[name] = jsonValue(value)
	end
	return result
end

local function readProperties(instance)
	local result = {}
	for _, propertyName in ipairs({
		"Value",
		"Disabled",
		"Enabled",
		"RunContext",
		"LinkedSource",
		"PackageId",
		"PackageContent",
		"PackageAssetId",
		"PackageLink",
		"PackageSource",
		"Text",
		"PlaceholderText",
		"ActionText",
		"ObjectText",
		"ToolTip",
	}) do
		local value = readProperty(instance, propertyName)
		if value ~= nil then
			result[propertyName] = jsonValue(value)
		end
	end
	return result
end

local function readSource(instance)
	if not instance:IsA("LuaSourceContainer") then
		return nil
	end
	local source = readProperty(instance, "Source")
	if typeof(source) ~= "string" then
		return nil
	end
	assert(#source <= MAX_SOURCE_BYTES, "A script exceeds the source size limit")
	return source
end

local instances = {}
local queue = {
	{
		instance = selected[1],
		parent = nil,
	},
}
local nextQueueIndex = 1

while nextQueueIndex <= #queue do
	assert(#instances < MAX_INSTANCES, "The selection exceeds the instance limit")

	local current = queue[nextQueueIndex]
	nextQueueIndex += 1

	local index = #instances
	local properties = readProperties(current.instance)
	local attributes = readAttributes(current.instance)
	local record = {
		name = current.instance.Name,
		class = current.instance.ClassName,
		tags = CollectionService:GetTags(current.instance),
	}
	if next(properties) ~= nil then
		record.properties = properties
	end
	if next(attributes) ~= nil then
		record.attributes = attributes
	end
	if current.parent ~= nil then
		record.parent = current.parent
	end
	local source = readSource(current.instance)
	if source ~= nil then
		record.source = source
	end
	instances[index + 1] = record

	for _, child in ipairs(current.instance:GetChildren()) do
		queue[#queue + 1] = {
			instance = child,
			parent = index,
		}
	end
end

local bundle = {
	schema_version = 1,
	instances = instances,
}

local encoded = HttpService:JSONEncode(bundle)
assert(#encoded <= MAX_BUNDLE_BYTES, "The bundle exceeds the MCP request size limit")
print(encoded)
