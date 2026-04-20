// Copyright 2026 Juan Pablo Tosso and the OWASP Coraza contributors
// SPDX-License-Identifier: Apache-2.0

//go:build ignore
// +build ignore

// gen_test_xml generates medium and large XML test fixtures with diverse
// structure: namespaces, attributes, CDATA, mixed content, deep nesting,
// processing instructions, and comments.
package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	generateMedium("medium_mixed.xml", 50)
	generateLarge("large_catalog.xml", 500)
	generateDeepNesting("medium_deep.xml", 30)
}

func generateMedium(filename string, count int) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	b.WriteString("\n")
	b.WriteString(`<?app-config version="2.0" mode="production"?>`)
	b.WriteString("\n")
	b.WriteString(`<!-- Medium-sized document with mixed content types -->`)
	b.WriteString("\n")
	b.WriteString(`<catalog xmlns="http://example.com/catalog"`)
	b.WriteString("\n")
	b.WriteString(`         xmlns:dc="http://purl.org/dc/elements/1.1/"`)
	b.WriteString("\n")
	b.WriteString(`         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"`)
	b.WriteString("\n")
	b.WriteString(`         version="3.1">`)
	b.WriteString("\n")

	categories := []string{"fiction", "science", "history", "tech", "art"}
	formats := []string{"hardcover", "paperback", "ebook", "audiobook"}

	for i := 1; i <= count; i++ {
		cat := categories[i%len(categories)]
		format := formats[i%len(formats)]
		b.WriteString(fmt.Sprintf(`  <book id="BK%04d" category="%s" format="%s" in-stock="%t">`+"\n",
			i, cat, format, i%3 != 0))
		b.WriteString(fmt.Sprintf(`    <dc:title lang="en">Book Title Number %d</dc:title>`+"\n", i))
		b.WriteString(fmt.Sprintf(`    <dc:creator role="author">Author %d</dc:creator>`+"\n", i%20+1))
		b.WriteString(fmt.Sprintf(`    <isbn>978-0-%07d-%d</isbn>`+"\n", i*1000+i, i%10))
		b.WriteString(fmt.Sprintf(`    <price currency="USD">%.2f</price>`+"\n", float64(10+i%90)+0.99))
		if i%5 == 0 {
			b.WriteString(`    <description><![CDATA[This book contains <special> characters & "quotes" that need CDATA.]]></description>` + "\n")
		} else if i%3 == 0 {
			b.WriteString(fmt.Sprintf(`    <description>A fascinating exploration of %s topics in volume %d.</description>`+"\n", cat, i))
		}
		if i%4 == 0 {
			b.WriteString(`    <reviews>` + "\n")
			for j := 1; j <= 3; j++ {
				b.WriteString(fmt.Sprintf(`      <review rating="%d" verified="%t">`+"\n", j+2, j%2 == 0))
				b.WriteString(fmt.Sprintf(`        <reviewer>User%d</reviewer>`+"\n", i*10+j))
				b.WriteString(fmt.Sprintf(`        <comment>Review comment %d for book %d</comment>`+"\n", j, i))
				b.WriteString(`      </review>` + "\n")
			}
			b.WriteString(`    </reviews>` + "\n")
		}
		if i%7 == 0 {
			b.WriteString(`    <!-- This book has special metadata -->` + "\n")
			b.WriteString(fmt.Sprintf(`    <metadata key="edition" value="%d"/>`+"\n", i%5+1))
			b.WriteString(fmt.Sprintf(`    <metadata key="pages" value="%d"/>`+"\n", 100+i*3))
		}
		b.WriteString(`  </book>` + "\n")
	}

	b.WriteString(`</catalog>` + "\n")
	writeFile(filename, b.String())
}

func generateLarge(filename string, count int) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<enterprise xmlns="http://example.com/enterprise"` + "\n")
	b.WriteString(`            xmlns:hr="http://example.com/hr"` + "\n")
	b.WriteString(`            xmlns:fin="http://example.com/finance"` + "\n")
	b.WriteString(`            xmlns:sec="http://example.com/security">` + "\n")

	departments := []string{"Engineering", "Marketing", "Sales", "Support", "Research", "Legal", "Finance", "HR"}
	roles := []string{"developer", "manager", "analyst", "director", "intern", "architect", "lead", "specialist"}
	locations := []string{"NYC", "SFO", "LON", "TKY", "BER", "SYD"}

	for i := 1; i <= count; i++ {
		dept := departments[i%len(departments)]
		role := roles[i%len(roles)]
		loc := locations[i%len(locations)]

		b.WriteString(fmt.Sprintf(`  <hr:employee id="EMP%05d" department="%s" clearance="level-%d">`+"\n",
			i, dept, i%5+1))
		b.WriteString(fmt.Sprintf(`    <hr:name>` + "\n"))
		b.WriteString(fmt.Sprintf(`      <hr:first>FirstName%d</hr:first>`+"\n", i))
		b.WriteString(fmt.Sprintf(`      <hr:last>LastName%d</hr:last>`+"\n", i))
		b.WriteString(`    </hr:name>` + "\n")
		b.WriteString(fmt.Sprintf(`    <hr:role>%s</hr:role>`+"\n", role))
		b.WriteString(fmt.Sprintf(`    <hr:location office="%s" remote="%t">%s Office</hr:location>`+"\n",
			loc, i%3 == 0, loc))

		b.WriteString(fmt.Sprintf(`    <fin:compensation>` + "\n"))
		b.WriteString(fmt.Sprintf(`      <fin:salary currency="USD">%d</fin:salary>`+"\n", 50000+i*100))
		b.WriteString(fmt.Sprintf(`      <fin:bonus percentage="%.1f"/>`+"\n", float64(i%20)+5.0))
		if i%3 == 0 {
			b.WriteString(`      <fin:stock-options vested="true">` + "\n")
			b.WriteString(fmt.Sprintf(`        <fin:grant shares="%d" price="%.2f"/>`+"\n", i*100, float64(50+i%200)+0.50))
			b.WriteString(`      </fin:stock-options>` + "\n")
		}
		b.WriteString(`    </fin:compensation>` + "\n")

		if i%5 == 0 {
			b.WriteString(`    <sec:access-log>` + "\n")
			for j := 1; j <= 5; j++ {
				b.WriteString(fmt.Sprintf(`      <sec:entry timestamp="2026-01-%02dT%02d:00:00Z" action="%s" resource="/api/v%d/data"/>`+"\n",
					j, j+8, []string{"read", "write", "admin"}[j%3], j%3+1))
			}
			b.WriteString(`    </sec:access-log>` + "\n")
		}

		if i%10 == 0 {
			b.WriteString(`    <hr:notes><![CDATA[Employee has special requirements: <confidential> data & "sensitive" info.]]></hr:notes>` + "\n")
		}

		// Mixed content element
		if i%8 == 0 {
			b.WriteString(fmt.Sprintf(`    <hr:bio>Employee %d joined in <hr:year>%d</hr:year> and works on <hr:project>Project-%s</hr:project>.</hr:bio>`+"\n",
				i, 2015+i%10, dept[:3]))
		}

		b.WriteString(`  </hr:employee>` + "\n")
	}

	b.WriteString(`</enterprise>` + "\n")
	writeFile(filename, b.String())
}

func generateDeepNesting(filename string, depth int) {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>` + "\n")
	b.WriteString(`<!-- Deeply nested structure to test XPath performance on deep trees -->` + "\n")
	b.WriteString(`<tree xmlns="http://example.com/tree" xmlns:meta="http://example.com/meta">` + "\n")

	// Generate a deeply nested structure with siblings at each level
	for i := 1; i <= depth; i++ {
		indent := strings.Repeat("  ", i)
		b.WriteString(fmt.Sprintf(`%s<level depth="%d" id="L%d">`+"\n", indent, i, i))
		b.WriteString(fmt.Sprintf(`%s  <meta:label>Level %d Node</meta:label>`+"\n", indent, i))
		b.WriteString(fmt.Sprintf(`%s  <data type="nested">Value at depth %d</data>`+"\n", indent, i))
		if i%5 == 0 {
			b.WriteString(fmt.Sprintf(`%s  <sibling order="1">Sibling A at depth %d</sibling>`+"\n", indent, i))
			b.WriteString(fmt.Sprintf(`%s  <sibling order="2">Sibling B at depth %d</sibling>`+"\n", indent, i))
		}
	}

	// Close all levels
	for i := depth; i >= 1; i-- {
		indent := strings.Repeat("  ", i)
		b.WriteString(fmt.Sprintf(`%s</level>`+"\n", indent))
	}

	b.WriteString(`</tree>` + "\n")
	writeFile(filename, b.String())
}

func writeFile(name, content string) {
	if err := os.WriteFile(name, []byte(content), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "error writing %s: %v\n", name, err)
		os.Exit(1)
	}
	fmt.Printf("Generated %s (%d bytes)\n", name, len(content))
}
