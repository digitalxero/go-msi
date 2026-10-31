package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	msi "go.digitalxero.dev/go-msi"
)

type collisionDB struct{ components []msi.Row }

func (d collisionDB) Tables() []string                { return []string{"Component"} }
func (d collisionDB) Table(string) ([]msi.Row, error) { return d.components, nil }
func (d collisionDB) Summary() msi.SummaryInfo        { return nil }

func TestCollisionAuditChoosesAccentedNameInEitherOrder(t *testing.T) {
	const accented = "RSUM~1.TXT|RÉSUMÉ.TXT"
	db := collisionDB{components: []msi.Row{{"Component": "ASCII", "Directory_": "INSTALLFOLDER"}, {"Component": "Unicode", "Directory_": "INSTALLFOLDER"}}}
	for _, reverse := range []bool{false, true} {
		rows := []msi.Row{{"Component_": "ASCII", "FileName": "OTHER.TXT"}, {"Component_": "Unicode", "FileName": accented}}
		if reverse {
			rows[0], rows[1] = rows[1], rows[0]
		}
		require.NotPanics(t, func() { auditCollision(db, rows) })
		for _, row := range rows {
			assert.Equal(t, accented, row["FileName"])
		}
	}
}

func TestCollisionAuditRejectsASCIIOnlyAndDifferentDirectories(t *testing.T) {
	db := collisionDB{components: []msi.Row{{"Component": "A", "Directory_": "ONE"}, {"Component": "B", "Directory_": "TWO"}}}
	require.PanicsWithValue(t, "collision has no accented filename", func() {
		auditCollision(db, []msi.Row{{"Component_": "A", "FileName": "A.TXT"}, {"Component_": "B", "FileName": "B.TXT"}})
	})
	require.PanicsWithValue(t, "collision files must share one physical directory", func() {
		auditCollision(db, []msi.Row{{"Component_": "A", "FileName": "RÉSUMÉ.TXT"}, {"Component_": "B", "FileName": "B.TXT"}})
	})
	db.components[1]["Directory_"] = "ONE"
	require.PanicsWithValue(t, "collision must cross distinct components", func() {
		auditCollision(db, []msi.Row{{"Component_": "A", "FileName": "RÉSUMÉ.TXT"}, {"Component_": "A", "FileName": "B.TXT"}})
	})
}
