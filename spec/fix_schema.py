# This script refactors the schema so oapi-codegen can generate models
# Concretely, inline definitions for oneOf, when a 'discriminator' is specified
# do not work. A reference is needed instead. By moving these inline definitions to their own
# component as <ParentComponent><DiscriminatorFieldValue> : {} (and referencing them
# where they were originally inlined) we can get oapi-codegen to stop complaining 
# about discriminator not being mapped for all schemas. 

import json
from typing import Union, Any, Dict
from copy import deepcopy

SCHEMA_FILE = "openapi.json"
OUT_SCHEMA_FILE = "openapi-refactored.json"
SKIP = [
    "TypedTransaction", # has no unique defined field to autogenerate a readable name
]

def PascalCase(s: str) -> str:
    sSplits = s.split("_")
    return "".join([s.capitalize() for s in sSplits])

# Get all nested oneOf nodes in the schema and the
# "key path" or order of key accesses (as a list) to the 
# oneOf node. The keyPath can contain integers/indices
# where a list was navigated.
def GetOneOf(node, keyPath):
    # for a list, recursively find oneOf values
    if isinstance(node, list):
        for idx, i in enumerate(node):
            keyPath.append(idx)
            for x, _ in GetOneOf(i, keyPath):
                yield x, keyPath
            keyPath.pop()
    # for a dictionary, yield "oneOf" value if it exists,
    elif isinstance(node, dict):
        if "oneOf" in node:
            yield node["oneOf"], keyPath
        # find "oneOf" in nested dict values recursively
        for i, j in node.items():
            keyPath.append(i)
            for x, _ in GetOneOf(j, keyPath):
                yield x, keyPath
            keyPath.pop()

# Given a key path, update the schema 
# in place with the update value
def UpdateSchema(keyPath: Union[str, int], update: Any, schema: Dict):
    currentVal = schema["components"]["schemas"]
    for key in keyPath[:-1]:
        currentVal = currentVal[key]
    currentVal.update({keyPath[-1]: update})

# Return the object at a given key path
def GetObject(keyPath: Union[str, int], schema: Dict) -> Any:
    currentVal = schema["components"]["schemas"]
    for key in keyPath:
        currentVal = currentVal[key]
    return currentVal

def Refactor(inFile, outFile):
    inSchema = json.load(inFile)
    outSchema = deepcopy(inSchema)
    oneOfGenerator = GetOneOf(inSchema["components"]["schemas"], [])
    # iterate over components in schemas

    for val, keyPath in oneOfGenerator:
        component = keyPath[0]
        if component in SKIP:
            continue

        # remove "oneOf" if there is only one item
        if len(val) == 1:
            UpdateSchema(keyPath, val[0], outSchema)
        # oneOf with no discriminator
        elif "discriminator" not in GetObject(keyPath, inSchema):
            newOneOfObjects = []
            for possibleValue in val:
                # prioritize title > enum > required field > type
                generatedSuffix = ""
                
                # Titles in our schema are self-sufficient for component names
                if "title" in possibleValue:
                    generatedSuffix = possibleValue["title"]
                    newCompName = "{}".format(generatedSuffix)

                elif "enum" in possibleValue and len(possibleValue["enum"]) == 1:
                    generatedSuffix = possibleValue["enum"][0]
                    newCompName = "{}{}".format(component, generatedSuffix)

                elif "required" in possibleValue and len(possibleValue["required"]) == 1:
                    generatedSuffix = possibleValue["required"][0]
                    newCompName = "{}{}".format(component, generatedSuffix)

                elif "type" in possibleValue:
                    generatedSuffix = PascalCase(possibleValue["type"])
                    newCompName = "{}{}".format(component, generatedSuffix)

                else:
                    # keep val as is
                    newOneOfObjects.append(possibleValue)
                    continue
                
                # refString to take place of original oneOf value
                refString = {"$ref": "#/components/schemas/{}".format(newCompName)}
                newOneOfObjects.append(refString)

                # as original becomes its own item in schema
                outSchema["components"]["schemas"][newCompName] = possibleValue

            UpdateSchema(keyPath + ["oneOf"], newOneOfObjects, outSchema)

            
        # oneOf with discriminator
        elif "discriminator" in GetObject(keyPath, inSchema):
            # read discriminator
            val = GetObject(keyPath, inSchema)
            discriminator = val["discriminator"]["propertyName"]
            print(f"Refactoring: {component} on discriminator: {discriminator}")

            # read actual values against these fields for each oneOF
            refStrings = []
            for possibleValue in val["oneOf"]:
                discValue = ""
                if "properties" not in possibleValue and "allOf" in possibleValue:
                    # find the right sub-component
                    for subComp in possibleValue["allOf"]:
                        if "properties" in subComp and discriminator in subComp["properties"]:
                            discValue = subComp["properties"][discriminator]['enum'][0]
                else:
                    discValue = possibleValue["properties"][discriminator]['enum'][0]

                # generate name for new component
                newComp = "{}{}".format(component, PascalCase(discValue))
                print(f"\tGenerating: {newComp}")

                # generate reference string
                refString = {"$ref": "#/components/schemas/{}".format(newComp)}
                refStrings.append(refString)

                # Add new component to outSchema
                outSchema["components"]["schemas"][newComp] = possibleValue

            # replace existing with reference
            UpdateSchema(keyPath + ["oneOf"], refStrings, outSchema)

    # write to file
    json.dump(outSchema, outFile, indent=2)

if __name__ == "__main__":
    with open(SCHEMA_FILE, "r") as inF:
        with open(OUT_SCHEMA_FILE, "w+") as outF:
            Refactor(inF, outF)
