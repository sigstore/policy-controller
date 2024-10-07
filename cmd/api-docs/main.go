//
// Copyright 2021 The Sigstore Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"bytes"
	"fmt"
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"text/template"
)

const (
	headerTemplate = `

# API Documentation ({{ .Version }})

> This document is automatically generated from the API definition in the code.
`
)

var (
	links = map[string]string{
		"metav1.ObjectMeta":           "https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#objectmeta-v1-meta",
		"metav1.ListMeta":             "https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#listmeta-v1-meta",
		"metav1.LabelSelector":        "https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#labelselector-v1-meta",
		"metav1.GroupVersionResource": "https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#groupversionresource-v1-meta",
		"v1.SecretReference":          "https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#secretreference-v1-core",
		"v1.LocalObjectReference":     "https://kubernetes.io/docs/reference/generated/kubernetes-api/v1.25/#localobjectreference-v1-core",
	}
	selfLinks = map[string]string{}
)

func main() {
	printAPIDocs(os.Args[1], os.Args[2:])
}

func toSectionLink(name string) string {
	name = strings.ToLower(name)
	name = strings.ReplaceAll(name, " ", "-")
	return name
}

func printTOC(types []KubeTypes) {
	fmt.Printf("\n## Table of Contents\n")
	for _, t := range types {
		strukt := t[0]
		if len(t) > 1 {
			fmt.Printf("* [%s](#%s)\n", strukt.Name, toSectionLink(strukt.Name))
		}
	}
}

func printAPIDocs(version string, paths []string) {
	header := struct {
		Version string
	}{
		Version: version,
	}
	t, err := template.New("header").Parse(headerTemplate)
	if err != nil {
		panic(err)
	}
	err = t.Execute(os.Stdout, header)
	if err != nil {
		panic(err)
	}

	types := ParseDocumentationFrom(paths)
	for _, t := range types {
		strukt := t[0]
		selfLinks[strukt.Name] = "#" + strings.ToLower(strukt.Name)
	}

	// we need to parse once more to now add the self links
	types = ParseDocumentationFrom(paths)

	printTOC(types)

	for _, t := range types {
		strukt := t[0]
		fmt.Printf("\n## %s\n\n%s\n\n", strukt.Name, strukt.Doc)
		if len(t) > 1 {
			fmt.Println("| Field | Description | Scheme | Required |")
			fmt.Println("| ----- | ----------- | ------ | -------- |")
			fields := t[1:]
			for _, f := range fields {
				fmt.Println("|", f.Name, "|", f.Doc, "|", f.Type, "|", f.Mandatory, "|")
			}
			fmt.Println("")
			fmt.Println("[Back to TOC](#table-of-contents)")
		}
	}
}

// Pair of strings. We keed the name of fields and the doc
type Pair struct {
	Name, Doc, Type string
	Mandatory       bool
}

// KubeTypes is an array to represent all available types in a parsed file. [0] is for the type itself
type KubeTypes []Pair

// ParseDocumentationFrom gets all types' documentation and returns them as an
// array. Each type is again represented as an array (we have to use arrays as we
// need to be sure for the order of the fields). This function returns fields and
// struct definitions that have no documentation as {name, ""}.
func ParseDocumentationFrom(srcs []string) []KubeTypes {
	var docForTypes []KubeTypes

	for _, src := range srcs {
		pkg := astFrom(src)
		if pkg == nil {
			continue
		}

		for _, kubType := range pkg.Types {
			if structType, ok := kubType.Decl.Specs[0].(*ast.TypeSpec).Type.(*ast.StructType); ok {
				var ks KubeTypes
				ks = append(ks, Pair{kubType.Name, fmtRawDoc(kubType.Doc), "", false})

				for _, field := range structType.Fields.List {
					typeString := fieldType(field.Type)
					fieldMandatory := fieldRequired(field)
					if n := fieldName(field); n != "-" {
						fieldDoc := fmtRawDoc(field.Doc.Text())
						ks = append(ks, Pair{n, fieldDoc, typeString, fieldMandatory})
					}
				}
				docForTypes = append(docForTypes, ks)
			}
		}
	}

	return docForTypes
}

func astFrom(filePath string) *doc.Package {
	fset := token.NewFileSet()
	m := make(map[string]*ast.File)

	f, err := parser.ParseFile(fset, filePath, nil, parser.ParseComments)
	if err != nil {
		fmt.Printf("failed to parse file %q: %v\n", filePath, err)
		return nil
	}

	m[filePath] = f
	apkg, _ := ast.NewPackage(fset, m, nil, nil) //nolint:staticcheck

	return doc.New(apkg, "", 0)
}

func fmtRawDoc(rawDoc string) string {
	var buffer bytes.Buffer
	delPrevChar := func() {
		if buffer.Len() > 0 {
			buffer.Truncate(buffer.Len() - 1) // Delete the last " " or "\n"
		}
	}

	// Ignore all lines after ---
	rawDoc = strings.Split(rawDoc, "---")[0]

	for _, line := range strings.Split(rawDoc, "\n") {
		line = strings.TrimRight(line, " ")
		leading := strings.TrimLeft(line, " ")
		switch {
		case len(line) == 0: // Keep paragraphs
			delPrevChar()
			buffer.WriteString("\n\n")
		case strings.HasPrefix(leading, "TODO"): // Ignore one line TODOs
		case strings.HasPrefix(leading, "+"): // Ignore instructions to go2idl
		default:
			if strings.HasPrefix(line, " ") || strings.HasPrefix(line, "\t") {
				delPrevChar()
				line = "\n" + line + "\n" // Replace it with newline. This is useful when we have a line with: "Example:\n\tJSON-someting..."
			} else {
				line += " "
			}
			buffer.WriteString(line)
		}
	}

	postDoc := strings.TrimRight(buffer.String(), "\n")
	postDoc = strings.ReplaceAll(postDoc, "\\\"", "\"") // replace user's \" to "
	postDoc = strings.ReplaceAll(postDoc, "\"", "\\\"") // Escape "
	postDoc = strings.ReplaceAll(postDoc, "\n", "\\n")
	postDoc = strings.ReplaceAll(postDoc, "\t", "\\t")
	postDoc = strings.ReplaceAll(postDoc, "|", "\\|")

	return postDoc
}

func toLink(typeName string) string {
	selfLink, hasSelfLink := selfLinks[typeName]
	if hasSelfLink {
		return wrapInLink(typeName, selfLink)
	}

	link, hasLink := links[typeName]
	if hasLink {
		return wrapInLink(typeName, link)
	}

	return typeName
}

func wrapInLink(text, link string) string {
	return fmt.Sprintf("[%s](%s)", text, link)
}

// fieldName returns the name of the field as it should appear in JSON format
// "-" indicates that this field is not part of the JSON representation
func fieldName(field *ast.Field) string {
	jsonTag := ""
	if field.Tag != nil {
		jsonTag = reflect.StructTag(field.Tag.Value[1 : len(field.Tag.Value)-1]).Get("json") // Delete first and last quotation
		if strings.Contains(jsonTag, "inline") {
			return "-"
		}
	}

	jsonTag = strings.Split(jsonTag, ",")[0] // This can return "-"
	if jsonTag == "" {
		if field.Names != nil {
			return field.Names[0].Name
		}
		return field.Type.(*ast.Ident).Name
	}
	return jsonTag
}

// fieldRequired returns whether a field is a required field.
func fieldRequired(field *ast.Field) bool {
	jsonTag := ""
	if field.Tag != nil {
		jsonTag = reflect.StructTag(field.Tag.Value[1 : len(field.Tag.Value)-1]).Get("json") // Delete first and last quotation
		return !strings.Contains(jsonTag, "omitempty")
	}

	return false
}

func fieldType(typ ast.Expr) string {
	switch e := typ.(type) {
	case *ast.Ident:
		return toLink(e.Name)
	case *ast.StarExpr:
		return toLink(fieldType(e.X))
	case *ast.SelectorExpr:
		pkg := e.X.(*ast.Ident) //nolint:errcheck
		t := e.Sel
		return toLink(pkg.Name + "." + t.Name)
	case *ast.ArrayType:
		return "[]" + toLink(fieldType(e.Elt))
	case *ast.MapType:
		return "map[" + toLink(fieldType(e.Key)) + "]" + toLink(fieldType(e.Value))
	default:
		return ""
	}
}
