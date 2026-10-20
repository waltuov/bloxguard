# Bundle format

`scan_bundle` accepts a flat JSON snapshot of an instance subtree. The flat form avoids recursive parsing and keeps parent relationships explicit.

## Schema

The top level object has two fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `schema_version` | integer | Must be `1`. |
| `instances` | array | Ordered instance records. |

Each instance can have these fields:

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | string | Instance name. |
| `class` | string | Roblox class name. |
| `parent` | integer or null | Zero based index of the parent. Roots use null or omit the field. |
| `properties` | object or empty array | Relevant properties such as `Value`, `RunContext`, `Disabled`, `Enabled`, `LinkedSource`, package link data such as `PackageId` and `PackageContent`, and shown text such as `Text` and `PlaceholderText`. An empty array is accepted as an empty object for Studio JSON compatibility. |
| `attributes` | object or empty array | Attribute names and JSON values. An empty array is accepted as an empty object for Studio JSON compatibility. |
| `tags` | array of strings | CollectionService tags. |
| `source` | string | Script source when available. |
| `source_file` | string | Optional source file label. |

`name` and `class` are required. Other instance fields use empty or absent values when unavailable. Unknown fields are rejected. A parent index must refer to an earlier item in the array.

## Example

This example is synthetic. Its ID is in the reserved fake range.

```json
{
  "schema_version": 1,
  "instances": [
    {
      "name": "FAKE_Model",
      "class": "Model",
      "parent": null,
      "properties": {},
      "attributes": {},
      "tags": []
    },
    {
      "name": "FAKE_ModuleId",
      "class": "NumberValue",
      "parent": 0,
      "properties": {
        "Value": 999000000000002
      },
      "attributes": {},
      "tags": []
    },
    {
      "name": "FAKE_Loader",
      "class": "Script",
      "parent": 0,
      "properties": {
        "Disabled": false,
        "RunContext": "Legacy"
      },
      "attributes": {},
      "tags": [],
      "source": "require(script.Parent.FAKE_ModuleId.Value)"
    }
  ]
}
```

The `parent` values are array indexes, not Roblox referents. The example loader has parent `0`, which points to `FAKE_Model`.

## Value encoding

Strings, numbers, and booleans keep their JSON types. The Studio snippet converts Roblox data types that JSON cannot represent into descriptive objects or strings. Rule resolution uses scalar values when it can do so without guessing.

`RunContext` is normalized to `Legacy`, `Server`, `Client`, or `Plugin`. Bundle input can use one of those names, a full name such as `Enum.RunContext.Client`, or the matching numeric enum value from 0 through 3.

Do not insert an executable payload to make a fixture realistic. Use `FAKE` names, asset IDs from `999000000000000` through `999999999999999`, and `https://discord.com/api/webhooks/000/FAKE` for a webhook shape.

## Completeness

The bundle itself has no completeness claim. `scan_bundle` validates every record and reports analysis completeness. Invalid schema versions, invalid parent indexes, excessive sizes, and analysis limits must not become a clean pass.

The reference exporter is [snapshot.luau](snapshot.luau). Review it before use. It reads only the selected subtree and prints JSON.
