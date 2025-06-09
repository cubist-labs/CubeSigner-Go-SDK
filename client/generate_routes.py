import json
import typing
import subprocess

# Configuration
CLIENT_NAME = "ApiClient"
SCHEMA_FILE = "../spec/openapi.json"
OUT_FILE = "routes.go"
MODELS_PACKAGE = "models"
# Do not generate these: we either provide
# our own implementation or do not need these
# routes in the SDK

# Endpoints with the following keywords in their path are skipped
SKIP_PATHS = ["internal"]
# Endpoint with these tags are skipped
SKIP_TAGS = set(["MMI"])
# Endpoints with these operation Ids are skipped
SKIP_OPERATION_IDS = set([
    "AboutMeLegacy", # Deprecating in favor of AboutMe
    "CreateSession", # Manual implementation for session management
    "DeriveKeyLegacy", # Deprecating in favor of DeriveKey
    "OidcAuth", # Manual implementation to provide Authorization header
    "MfaEmailInit",  # Manual implementation to return email challenge
    "Oauth2TokenRefresh" # Manual implementation to allow contentType header as parameter
    ])

# The following endpoints may require MFA. This sets
# their response type accordingly. The schema
# may not list a 202 response explicitly and
# certain endpoints can be configured to require
# Mfa via policies.
# TODO: We should update the schema altogether to
# reflect correct responses w.r.t MFA
MFA_REQUIRED = set([
    "CreateSession",
    "UserDeleteTotp",
    "UpdateKey",
    "DeleteKey",
    "DeleteRole",
    "UpdateRole",
    "AddKeysToRole",
    "RemoveKeyFromRole",
    "AddUserToRole",
    "RemoveUserFromRole",
    "UserDeleteFido"
    ])

# Rename the following methods.
# Maps operationIds from schema to
# new names
RENAME = {
    "eth1Sign": "EvmSign"
}

# The main template for endpoint method on client.
TEMPLATE_METHOD = """

{desc}
func {receiverDec} {funcName}({paramList}) ({returnTypes}) {{
{queryParamStatements} {unauthClientDec}
    resp, err := client.{sendMethod}(&payload{{
{payloadString}
    }})
{returnStatements}
}}

"""

# Template for query param struct
TEMPLATE_QPARAMS = """

type {typeName} struct {{
{fields}
}}

"""

# Static routes that do not require a session use this template to 
# declare a client that uses a fake session manager.
TEMPLATE_CLIENT_DEC = """
    client, err := NewApiClient(&noSessionManager{{ {params} }})
    if err != nil {{
        return nil, err
    }}"""

def customCapitalize(s: str) -> str:
    s = s.strip()
    s = s.replace(".", "-")
    s = s.replace("_", "-")
    # when capitalizing to Type name preserve any
    if s == "any":
        return s
    sSplits = s.split("-")
    for i in range(len(sSplits)):
        sSplits[i] = sSplits[i][0].upper() + sSplits[i][1:]
    return "".join(sSplits)

def convertToCamel(s: str) -> str:
    s = s.strip()
    s = s.replace(".", "_")
    sSplits = s.split("_")
    for i in range(len(sSplits)):
        if i > 0:
            sSplits[i] = sSplits[i][0].upper() + sSplits[i][1:]
        elif i == 0:
            sSplits[i] = sSplits[i][0].lower() + sSplits[i][1:]

    return "".join(sSplits)

# Add MODELS_PACKAGE identifier before the types.
# This is needed as the types are imported from "models"
# package and need to represented as <MODELS_PACKAGE>.<Type>. 
def prependModelsPackage(s: str) -> str:
    if s == "any":
        return s
    pointer = False
    if s[0] == '*':
        pointer = True
        s = s[1:]

    s= "{}.{}".format(MODELS_PACKAGE, s)
    if pointer:
        s = "*" + s
    return s

# A helper to create a string in the form "key": keyToCamelCase.
# which reflects "<raw parameter name in schema>" : <go variable name>
def makeKeyValString(key: str, required: bool) -> str:
    # derefernce if optional
    val = "*" if not required else "" 
    val += convertToCamel(key)
    return "\"{}\": {}".format(key, val)

# A helper function to check if any SKIP_PATH key words occur as
# substring
def skipPath(path: str) -> bool:
    for kw in SKIP_PATHS:
        if kw in path:
            return True
    return False

# Translate openapi "primitive" types to go lang types. Additionally
# convert to pointer if optional.
def getPrimitiveTypeString(schema: str, required: bool) -> str:
    typeMap = {
        "integer": "uint64",
        "string": "string",
        "boolean": "bool",
        "object": "any"
    }
    typeStr = "string"
    if "type" in schema:
        typeStr = typeMap[schema["type"]]
    if not required and typeStr != "any":
        typeStr = "*"+typeStr
    return typeStr

# Read the requestBody datatype from openapi schema. This is used to:
# 1) Determine the return type (TODO: unused as of now)
# 2) Construct go variable name by converting the datatype to camelCase.
def getRequestBodyType(reqBody: dict[str, typing.Any]) -> str:
    schema = reqBody["content"]["application/json"]["schema"]
    typeStr = ""
    if "type" in schema:
        typeStr += getPrimitiveTypeString(schema, True)
    elif "$ref" in schema:
        typeStr += schema["$ref"].strip().split('/')[-1]
    elif "allOf" in schema:
        typeStr += schema["allOf"][0]["$ref"].strip().split('/')[-1]

    if typeStr == "Empty" or typeStr == "":
        return ""

    if "required" not in reqBody or not reqBody["required"]: 
        typeStr = "*" + typeStr

    return typeStr

# Variable names are camelcase versions of their
# datatype. `any` is always a requestBody.
def typeToVarname(s: str) -> str:
    if s == "": 
        return ""
    if s[0] == "*":
        s = s[1:]
    if s == "any":
        s = "requestBody"
    return convertToCamel(s)

# Convert description from openapi spec to
# doc comment
def makeDocComment(desc: str) -> str:
    if desc == "": 
        return ""
    commentLines = []
    for line in desc.splitlines():
        line = "// " + line
        commentLines.append(line)

    return "\n".join(commentLines)

# Query parameters can be optional. They need to be added to the
# `queryParams` map only if non nil.
#
# This function returns appropriate statement needed to
# handle a query parameter, .e.g, if not nil add to map:
# "page.size", "page.start" parameters have their own handler
# in the go sdk, and always occur together.
def getQueryParamStatement(paramAsDict) -> str:
    paramName = paramAsDict["name"]
    required = paramAsDict["required"]
    goVarName = convertToCamel(paramName)
    structName = "queryParameters"
    structFieldName = customCapitalize(paramName)

    if required:
        return "queryParams[\"{}\"] = {}.{}".format(paramName, structName, structFieldName)

    # For optional query parameters add non nil checks (if statements), Additionally,
    # we may need to convert non-string values to strings with fmt.Sprintf.
    toString = ""
    if "type" not in paramAsDict["schema"] or paramAsDict["schema"]["type"] != "string":
        # type exists and is not string we need to covert it
        toString = "{varname}Str := fmt.Sprintf(\"%v\", *{structName}.{fieldName})".format(varname = goVarName, structName = structName, fieldName = structFieldName)

    # return an if statement which will 1) convert to string if needed 2) add non-nil string value to queryParams
    return """\tif {structName}.{fieldName} != nil {{
    {toString}
    queryParams[\"{param}\"] = {varnameORstr}
}}""".format(param = paramName, 
                structName = structName,
                fieldName = structFieldName,
                toString = toString, 
                varnameORstr = f"*{structName}.{structFieldName}" if toString == "" else f"{goVarName}Str")

# Determine if an MFA response is expected. This is used to set the go method
# return type to CubeSignerResponse (for MFA) vs. setting it to GenericHttpResponse
# (where MFA is never expected)
def getReturnTypes(methodInfo: dict[str, typing.Any]) -> tuple[str, str, bool]:
    returnSignature = "*GenericHttpResponse, error"
    returnType = ""
    isMfa = False
    if (("responses" in methodInfo and "202" in methodInfo["responses"]) or 
        ("Signing" in methodInfo["tags"]) or 
        customCapitalize(methodInfo["operationId"]) in MFA_REQUIRED):

        returnSignature = "*CubeSignerResponse[GenericHttpResponse], error"
        isMfa = True
    
    # finally check if a response component is present and replace GenericHttpResponse
    if "responses" in methodInfo and "200" in methodInfo["responses"] and "$ref" in methodInfo["responses"]["200"]:
        returnType = methodInfo["responses"]["200"]["$ref"].split("/")[-1]
        returnType = prependModelsPackage(returnType)
        returnSignature = returnSignature.replace("GenericHttpResponse", returnType)

    return returnSignature, returnType, isMfa

# A helper function to extract parameter information and
# construct formatted strings for: method signature (parameters),
# pathParams map passed to payload, and query parameter statements.
def parseParams(paramList: list[typing.Any], methodName: str) -> tuple[str, str, str, str]:
    queryParamStrings = []
    pathParamStrings = []
    methodSignatureStrings = []
    queryParamStatements = ""
    # This flag will latch to True if a required
    # query parameter is seen. In this case
    # the params struct will not be a pointer
    # We also need an additional nil check 
    # for the struct itself
    requiredQueryParam = False

    for paramAsDict in paramList:
        # handled by client
        if paramAsDict["name"] == "org_id":
            continue

        # handle everything else
        typeStr = getPrimitiveTypeString(paramAsDict["schema"], paramAsDict["required"])

        if paramAsDict["in"] == "path":
            pathParamStrings.append(makeKeyValString(paramAsDict["name"], paramAsDict["required"]))
            # path params go in method signatures as is
            methodSignatureStrings.append(convertToCamel(paramAsDict["name"] + " " + typeStr))

        if paramAsDict["in"] == "query":
            if paramAsDict["required"]:
                requiredQueryParam = True
            queryStatement = getQueryParamStatement(paramAsDict)
            queryParamStrings.append(queryStatement)

    # If query parameters were present, format the structure and statements
    if len(queryParamStrings):
        if requiredQueryParam:
            methodSignatureStrings.append(f"queryParameters {MODELS_PACKAGE}.{methodName}Params")
            queryParamStatements = "\n".join(queryParamStrings)
        else:
            methodSignatureStrings.append(f"queryParameters *{MODELS_PACKAGE}.{methodName}Params")
            queryParamStatements = "if queryParameters != nil {{{}}}".format("\n".join(queryParamStrings))

    return(
        ", ".join(methodSignatureStrings) if len(methodSignatureStrings) else "",
        ("map[string]string{" + ", ".join(pathParamStrings) + "}") if len(pathParamStrings) else "",
        queryParamStatements,
    )       

def GenerateFromSchema(gf):
    with open(SCHEMA_FILE, "r") as f:
        schema = json.load(f)
        # iterate over each path
        for path in schema["paths"]:
            # skip based on paths
            if skipPath(path):
                continue
            #iterate over methods for a path
            for method in schema["paths"][path]:
                methodInfo = schema["paths"][path][method]
                # skip based on tags 
                if len(set(methodInfo["tags"]).intersection(SKIP_TAGS)):
                    continue

                # skip based on operationId
                if customCapitalize(methodInfo["operationId"]) in SKIP_OPERATION_IDS:
                    continue
                
                # get method info
                print(path, ":", method)

                # get method security
                security = ""
                securityTypesList = methodInfo["security"]
                assert len(securityTypesList) <= 1, "Unexpected: Multiple types of security items found"
                if len(securityTypesList):
                    securityTypeItem = list(securityTypesList[0].keys())
                    assert len(securityTypeItem) <= 1, "Unexpected: Multiple types of security found"
                    if len(securityTypeItem):
                        security = securityTypeItem[0]

                isStatic = security != "SignerAuth"

                # Process doc comment
                desc = makeDocComment(methodInfo["description"] if "description" in methodInfo else "")
                
                # Payload always has method and path
                payloadString = """\t\tmethod: \"{}\",\n\t\tpath: \"{}\",""".format(method.upper(), path)
                # Other payload fields may be optional
                methodParamString, pathParamsString, queryParamStatements = parseParams(methodInfo["parameters"] if "parameters" in methodInfo else [], customCapitalize(methodInfo["operationId"]))
                if pathParamsString != "": 
                    payloadString += "\n\t\tpathParams: {},".format(pathParamsString)
                if queryParamStatements != "":
                    queryParamStatements = "\tqueryParams := make(map[string]string)\n" + queryParamStatements
                    payloadString += "\n\t\tqueryParams: queryParams,"

                requestBodyType = (getRequestBodyType(methodInfo["requestBody"]) if "requestBody" in methodInfo else "")
                if requestBodyType != "":
                    payloadString += "\n\t\tbody: {},".format(typeToVarname(requestBodyType))
                    # add request body 
                    if methodParamString != "":
                        methodParamString += ", {} {}".format(typeToVarname(requestBodyType), prependModelsPackage(requestBodyType))
                    else:
                        methodParamString = "{} {}".format(typeToVarname(requestBodyType), prependModelsPackage(requestBodyType))

                # check if response may require MFA and set return types
                returnSignature, returnType, isMfa = getReturnTypes(methodInfo)
                if isMfa:
                    # add receipts to params and payload
                    if methodParamString != "":
                        methodParamString += ", {} {}".format("mfaReceipts", "...*MfaReceipt")
                    else:
                        methodParamString = "{} {}".format("mfaReceipts", "...*MfaReceipt")

                    payloadString += "\n\t\tmfaReceipts: mfaReceipts,"

                # if return type is non generic, parse it before returning
                returnStatements = "\treturn resp, err\n"
                if returnType != "":
                    returnStatements= "\tif err != nil {return nil, err}\n"
                    if not isMfa:
                        returnStatements += "\treturn ParseGenericResponseInto[{}](resp)\n".format(returnType)
                    else:
                        returnStatements += "\treturn newCubeSignerResponseFrom[{}](resp)\n".format(returnType)
                
                # if security is of type "Oidc" we need to add idToken as a method parameter. IdToken will also be the Authorization header
                # For the remaining two types of security: 
                # "SignerAuth" is managed by SessionManagers = No action needed
                # No/empty security Authorization header is ignored altogether = No action needed
                if security == "Oidc":
                    methodParamString = "idToken string, " + methodParamString
                    payloadString += "\n\t\theaders: map[string]string{\"Authorization\": idToken},"
                if isStatic and "{org_id}" in path:
                    methodParamString = "orgId string, " + methodParamString
                if isStatic:
                    methodParamString = "env session.EnvInterface, " + methodParamString

                # Add client declaration if isStatic
                clientDec = ""
                if isStatic:
                    clientParamString = "RootUrl: env.Spec.SignerApiRoot"
                    clientParamString = "OrgID: orgId, " + clientParamString if "{org_id}" in path else clientParamString
                    clientDec = TEMPLATE_CLIENT_DEC.format(
                        params = clientParamString
                    )


                finalString = TEMPLATE_METHOD.format(
                    desc = desc,
                    receiverDec = "" if isStatic else f"(client *{CLIENT_NAME})",
                    unauthClientDec = clientDec,
                    funcName = RENAME[methodInfo["operationId"]] if methodInfo["operationId"] in RENAME else customCapitalize(methodInfo["operationId"]),
                    paramList = methodParamString,
                    queryParamStatements = queryParamStatements,
                    returnTypes = returnSignature,
                    sendMethod = "send" if isMfa else "sendAndAssertNoMfa",
                    payloadString = payloadString,
                    returnStatements = returnStatements
                )

                gf.write(finalString)

if __name__ == "__main__":
    with open(OUT_FILE, "w+") as gf:
    # add package header amd import
        autoGenFileHeader = """// This file provides various API endpoint methods on ApiClient.
//
// Code is auto-generated for cubesigner_go_sdk. DO NOT EDIT.

"""
        gf.write(autoGenFileHeader)
        gf.write("package client\n")
        gf.write("import (\"fmt\"\n\n")
        gf.write("\"github.com/cubist-labs/cubesigner-go-sdk/models\"\n")
        gf.write("\"github.com/cubist-labs/cubesigner-go-sdk/session\")\n")

        GenerateFromSchema(gf)

