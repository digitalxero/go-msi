package msi

// msi_validation_table.go
// The _Validation system table (Microsoft Learn -validation-table) describes
// every column of every persistent table: nullability, numeric range, foreign
// key target, category and permitted value set. Unlike _Tables/_Columns it is
// a NORMAL persistent table: it is listed in _Tables, has rows in _Columns,
// and contains 10 rows describing its own columns. msiexec itself does not
// require it, but Orca/ICE validation and msitools expect it, so we emit it.
// Row content is sourced from the canonical catalog (msi_table_catalog.go).

import (
	"fmt"
	"sort"
)

const msiValidationTableName = "_Validation"

// createMSIValidationTable returns the empty _Validation table schema
// (Table s32 key, Column s32 key, Nullable s4, MinValue I4, MaxValue I4,
// KeyTable S255, KeyColumn I2, Category S32, Set S255, Description S255).
func createMSIValidationTable() msiTable {
	return createMSITableFromCatalog(msiValidationTableName)
}

// populateMSIValidationRows builds the _Validation table containing one row
// per column of every catalog-known table present in tables, plus _Validation
// itself. Tables absent from the catalog (custom tables) are skipped without
// error; their rows are the responsibility of whoever defines them.
//
// NULL semantics per the -validation-table docs: MinValue/MaxValue apply only
// to numeric columns and are NULL (stored 0 on disk) when not applicable; a
// real range bound of 0 is stored as 0^0x80000000, so NULL and 0 remain
// distinct. KeyTable/KeyColumn/Category/Set are NULL when not applicable.
// Rows are inserted in sorted table-name order for determinism; the on-disk
// order is decided at serialization time by the (Table, Column) pool-ID sort.
func populateMSIValidationRows(tables map[string]msiTable) (msiTable, error) {
	vt := createMSIValidationTable()

	names := make([]string, 0, len(tables)+1)
	for n := range tables {
		names = append(names, n)
	}
	if _, ok := tables[msiValidationTableName]; !ok {
		names = append(names, msiValidationTableName)
	}
	sort.Strings(names)

	for _, n := range names {
		def, ok := msiCatalogTable(n)
		if !ok {
			continue
		}
		for _, cc := range def.columns {
			nullable := "N"
			if cc.nullable {
				nullable = "Y"
			}
			row := newMSIRowBuilder().WithColumns(vt.columns()...).WithValues(
				def.name,
				cc.name,
				nullable,
				msiNullableInt32(cc.minValue),
				msiNullableInt32(cc.maxValue),
				msiNullableString(cc.keyTable),
				msiNullableInt16(cc.keyColumn),
				msiNullableString(cc.category),
				msiNullableString(cc.set),
				msiNullableString(cc.description),
			).Build()
			if err := vt.addRow(row); err != nil {
				return nil, fmt.Errorf("_Validation row for %s.%s: %w", def.name, cc.name, err)
			}
		}
	}
	return vt, nil
}

// msiNullableInt32 maps a catalog *int32 to a row value (nil stays NULL).
func msiNullableInt32(p *int32) any {
	if p == nil {
		return nil
	}
	return *p
}

// msiNullableInt16 maps a catalog *int16 to a row value (nil stays NULL).
func msiNullableInt16(p *int16) any {
	if p == nil {
		return nil
	}
	return *p
}

// msiNullableString maps a catalog string to a row value ("" stays NULL).
func msiNullableString(s string) any {
	if s == "" {
		return nil
	}
	return s
}
