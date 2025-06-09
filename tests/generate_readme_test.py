import re

TEST_TEMPLATE = """
package test

{imports}

{otherFuncs}

func TestReadMe(t *testing.T) {{
{statements}
}}
"""

README_PATH = "../README.md"
OUTFILE = "readme_test.go"

if __name__ == "__main__":

    data = ""
    with open(README_PATH, "r") as rFile:
        data = rFile.read()

    # print(data)
    pattern = r'^```go(?:\w+ )?\s*\n(.*?)(?=^```)'
    codeLines = re.findall(pattern, data, re.DOTALL | re.MULTILINE)

    importStr = codeLines[0]
    importStr = importStr.replace("(\n", "(\n\t\"testing\"\n")

    code = TEST_TEMPLATE.format(imports = importStr, otherFuncs = codeLines[1], statements = "\n".join(codeLines[2:]))
    # replace place holder ID and Gamma env with test values
    code = code.replace("\"Org#...\"", "apiClient.Manager.Metadata().OrgID")
    code = code.replace("env.Gamma", "session.EnvInterface{Spec: &session.Spec{SignerApiRoot: apiClient.RootUrl}}")
    # env package import is not needed after test value substitution
    code = code.replace("\"github.com/cubist-labs/cubesigner-go-sdk/spec/env\"\n", "")

    with open(OUTFILE, "w+") as oFile:
        oFile.write(code)