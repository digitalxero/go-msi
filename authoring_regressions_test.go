package msi_test

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	msi "go.digitalxero.dev/go-msi"
)

func authoringPackage(payload string) msi.PackageBuilder {
	b := msi.NewPackage().WithProductCode("{33445566-7788-4999-AAAA-BBCCDDEEFF00}").
		WithUpgradeCode("{11223344-5566-4777-8888-99AABBCCDDEE}").WithProductName("Authoring Regression").
		WithManufacturer("Regression").WithVersion("1.0.0")
	b.RootDirectory("INSTALLFOLDER", "Authoring Regression").Component("Payload").AssociateToFeature("Main").
		WithFile("payload.txt", msi.FileSourceFromBytes([]byte(payload)))
	b.Feature("Main").WithTitle("Main").WithLevel(1)
	return b
}

func authoredBytes(t *testing.T, b msi.PackageBuilder) ([]byte, msi.Database) {
	t.Helper()
	p, err := b.Build()
	require.NoError(t, err)
	var out bytes.Buffer
	require.NoError(t, p.WriteMSI(&out))
	db, err := msi.Open(bytes.NewReader(out.Bytes()))
	require.NoError(t, err)
	return out.Bytes(), db
}

func TestPackageCodeCoversAuthoredContent(t *testing.T) {
	baseline, db := authoredBytes(t, authoringPackage("PAYLOAD-A"))
	repeated, same := authoredBytes(t, authoringPackage("PAYLOAD-A"))
	assert.Equal(t, baseline, repeated)
	assert.Equal(t, db.Summary().Revision(), same.Summary().Revision())
	cases := map[string]func(msi.PackageBuilder){
		"payload": func(b msi.PackageBuilder) {
			b.Directory("INSTALLFOLDER").Component("Payload").WithFile("payload.txt", msi.FileSourceFromBytes([]byte("PAYLOAD-B")))
		},
		"registry": func(b msi.PackageBuilder) {
			b.Directory("INSTALLFOLDER").Component("Payload").RegistryKey(msi.RegistryRootHKCU, `Software\AuthoringRegression`).Value("Value", "changed")
		},
		"script": func(b msi.PackageBuilder) {
			b.CustomAction("Script").VBScriptInline("x = 1").ScheduleAfter(msi.InstallExecuteSequence, "InstallFiles", "NOT Installed")
		},
		"binary":     func(b msi.PackageBuilder) { b.Binary("Data", msi.FileSourceFromBytes([]byte("binary"))) },
		"UI":         func(b msi.PackageBuilder) { b.WithMinimalUI() },
		"metadata":   func(b msi.PackageBuilder) { b.WithManufacturer("Different") },
		"property":   func(b msi.PackageBuilder) { b.WithProperty("EXAMPLE", "changed") },
		"privileges": func(b msi.PackageBuilder) { b.WithElevatedPrivileges(false) },
		"transform": func(b msi.PackageBuilder) {
			b.WithLanguageTransform(msi.LangCode_deDE, func(t msi.PackageBuilder) { t.WithProductName("Andere") })
		},
	}
	for name, configure := range cases {
		t.Run(name, func(t *testing.T) {
			b := authoringPackage("PAYLOAD-A")
			if name == "payload" {
				b = authoringPackage("PAYLOAD-B")
			} else {
				configure(b)
			}
			data, changed := authoredBytes(t, b)
			assert.NotEqual(t, baseline, data)
			assert.NotEqual(t, db.Summary().Revision(), changed.Summary().Revision())
			for _, table := range []string{"Component", "FeatureComponents"} {
				before, err := db.Table(table)
				require.NoError(t, err)
				after, err := changed.Table(table)
				require.NoError(t, err)
				assert.Equal(t, before, after, "stable resource identities")
			}
			props, err := changed.Table("Property")
			require.NoError(t, err)
			for _, row := range props {
				if row["Property"] == "ProductCode" {
					assert.Equal(t, "{33445566-7788-4999-AAAA-BBCCDDEEFF00}", row["Value"])
				}
				if row["Property"] == "UpgradeCode" {
					assert.Equal(t, "{11223344-5566-4777-8888-99AABBCCDDEE}", row["Value"])
				}
			}
		})
	}
}

func TestShortNameLiteralReservation(t *testing.T) {
	for _, directory := range []bool{false, true} {
		for _, reverse := range []bool{false, true} {
			for _, literal := range []string{"abcdef~1.txt", "ABCDEF~1.TXT"} {
				t.Run(fmt.Sprintf("directory=%v/reverse=%v/%s", directory, reverse, literal), func(t *testing.T) {
					b := authoringPackage("base")
					names := []string{"abcdef1long.txt", literal, "abcdef2long.txt"}
					if reverse {
						names[0], names[1] = names[1], names[0]
					}
					for i, name := range names {
						if directory && i == 0 {
							b.Directory("INSTALLFOLDER").Subdirectory("Child", name).Component("ChildPayload").AssociateToFeature("Main").WithFile("child.txt", msi.FileSourceFromBytes([]byte("child")))
						} else {
							b.Directory("INSTALLFOLDER").Component(fmt.Sprintf("Sibling%d", i)).AssociateToFeature("Main").WithFile(name, msi.FileSourceFromBytes([]byte(name)))
						}
					}
					_, db := authoredBytes(t, b)
					used := map[string]bool{}
					add := func(value string) {
						short := strings.ToUpper(strings.Split(value, "|")[0])
						assert.False(t, used[short], "duplicate short name %s", short)
						used[short] = true
					}
					rows, err := db.Table("File")
					require.NoError(t, err)
					for _, row := range rows {
						if row["Component_"] != "ChildPayload" {
							add(row["FileName"].(string))
						}
					}
					rows, err = db.Table("Directory")
					require.NoError(t, err)
					for _, row := range rows {
						if row["Directory_Parent"] == "INSTALLFOLDER" {
							add(row["DefaultDir"].(string))
						}
					}
				})
			}
		}
	}
}

func TestMinimalUIProgressReturnsToExecuteAction(t *testing.T) {
	_, db := authoredBytes(t, authoringPackage("base").WithMinimalUI())
	rows, err := db.Table("Dialog")
	require.NoError(t, err)
	for _, row := range rows {
		if row["Dialog"] == "ProgressDlg" {
			assert.Zero(t, row["Attributes"].(int32)&int32(msi.DialogModal), "progress must be modeless")
		}
	}
	rows, err = db.Table("InstallUISequence")
	require.NoError(t, err)
	seq := map[string]int16{}
	for _, row := range rows {
		seq[row["Action"].(string)] = row["Sequence"].(int16)
	}
	assert.Less(t, seq["WelcomeDlg"], seq["ProgressDlg"])
	assert.Less(t, seq["ProgressDlg"], seq["ExecuteAction"])
	assert.Equal(t, int16(-1), seq["ExitDialog"])
	assert.Equal(t, int16(-2), seq["UserExit"])
	assert.Equal(t, int16(-3), seq["FatalError"])
	rows, err = db.Table("ControlEvent")
	require.NoError(t, err)
	found := false
	for _, row := range rows {
		if row["Dialog_"] == "WelcomeDlg" && row["Control_"] == "Install" {
			assert.Equal(t, "EndDialog", row["Event"])
			assert.Equal(t, "Return", row["Argument"])
			assert.Equal(t, `AgreeToLicense = "1"`, row["Condition"])
			found = true
		}
	}
	assert.True(t, found)
}

func TestRejectUnsupportedWindowsNames(t *testing.T) {
	for _, name := range []string{"NUL.txt", "con", "PRN.log", "AuX", "COM1.log", "LPT9", "COM¹.txt", "LPT²", "com³.dat", "readme.txt.", "readme.txt "} {
		for _, directory := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/directory=%v", name, directory), func(t *testing.T) {
				b := authoringPackage("base")
				if directory {
					b.Directory("INSTALLFOLDER").Subdirectory("Invalid", name)
				} else {
					b.Directory("INSTALLFOLDER").Component("Invalid").AssociateToFeature("Main").WithFile(name, msi.FileSourceFromBytes([]byte("bad")))
				}
				p, err := b.Build()
				require.NoError(t, err)
				var out bytes.Buffer
				err = p.WriteMSI(&out)
				require.Error(t, err)
				assert.Contains(t, err.Error(), name)
				assert.Empty(t, out.Bytes())
			})
		}
	}
}

func TestWindowsNamesAndDirectorySyntax(t *testing.T) {
	for _, name := range []string{".config", "résumé.txt", "日本語.txt", "COM0.txt", "COM10.txt", "LPT0", "NULling", "a b.txt"} {
		t.Run(name, func(t *testing.T) {
			b := authoringPackage("base")
			b.Directory("INSTALLFOLDER").Subdirectory("Valid", name).Component("ValidPayload").AssociateToFeature("Main").WithFile(name, msi.FileSourceFromBytes([]byte("valid")))
			_, db := authoredBytes(t, b)
			files, err := db.Table("File")
			require.NoError(t, err)
			for _, row := range files {
				if row["Component_"] == "ValidPayload" {
					assert.True(t, strings.HasSuffix(row["FileName"].(string), name))
				}
			}
		})
	}
	for _, syntax := range []string{".", ".:source", "target:.", "SHORT|Long Directory:SRC|Source Directory", "target:source"} {
		t.Run(syntax, func(t *testing.T) {
			b := authoringPackage("base")
			b.Directory("INSTALLFOLDER").Subdirectory("Syntax", syntax)
			_, db := authoredBytes(t, b)
			rows, err := db.Table("Directory")
			require.NoError(t, err)
			for _, row := range rows {
				if row["Directory"] == "Syntax" {
					assert.NotEmpty(t, row["DefaultDir"])
				}
			}
		})
	}
	for _, syntax := range []string{"NUL:source", "target:COM¹", "SHORT|NUL.txt", "NUL|Valid Name", "target:source.", "a:b:c"} {
		t.Run(syntax, func(t *testing.T) {
			b := authoringPackage("base")
			b.Directory("INSTALLFOLDER").Subdirectory("Syntax", syntax)
			p, err := b.Build()
			require.NoError(t, err)
			var out bytes.Buffer
			require.Error(t, p.WriteMSI(&out))
			assert.Empty(t, out.Bytes())
		})
	}
}

func TestRejectCaseOnlySiblingNames(t *testing.T) {
	for _, directory := range []bool{false, true} {
		b := authoringPackage("base")
		b.Directory("INSTALLFOLDER").Component("One").AssociateToFeature("Main").WithFile("same.txt", msi.FileSourceFromBytes([]byte("one")))
		if directory {
			b.Directory("INSTALLFOLDER").Subdirectory("Two", "SAME.TXT")
		} else {
			b.Directory("INSTALLFOLDER").Component("Two").AssociateToFeature("Main").WithFile("SAME.TXT", msi.FileSourceFromBytes([]byte("two")))
		}
		p, err := b.Build()
		require.NoError(t, err)
		var out bytes.Buffer
		require.Error(t, p.WriteMSI(&out))
		assert.Empty(t, out.Bytes())
	}
}

func TestDotDirectorySharesShortNameNamespace(t *testing.T) {
	b := authoringPackage("base")
	b.Directory("INSTALLFOLDER").Component("Long").AssociateToFeature("Main").WithFile("abcdef1long.txt", msi.FileSourceFromBytes([]byte("long")))
	b.Directory("INSTALLFOLDER").Subdirectory("Dot", ".").Component("Literal").AssociateToFeature("Main").WithFile("abcdef~1.txt", msi.FileSourceFromBytes([]byte("literal")))
	_, db := authoredBytes(t, b)
	rows, err := db.Table("File")
	require.NoError(t, err)
	for _, row := range rows {
		if row["Component_"] == "Long" {
			assert.Equal(t, "ABCDEF~2.TXT|abcdef1long.txt", row["FileName"])
		}
	}
}

func TestPackageCodeCoversChangedBinaryAndTransformData(t *testing.T) {
	for _, kind := range []string{"binary", "transform", "license"} {
		makePackage := func(value string) msi.PackageBuilder {
			b := authoringPackage("base")
			switch kind {
			case "binary":
				b.Binary("Asset", msi.FileSourceFromBytes([]byte(value)))
			case "transform":
				b.WithLanguageTransform(msi.LangCode_deDE, func(t msi.PackageBuilder) { t.WithProperty("TRANSLATED", value) })
			case "license":
				b.WithMinimalUI().WithLicenseText(value)
			}
			return b
		}
		_, a := authoredBytes(t, makePackage("value A"))
		_, b := authoredBytes(t, makePackage("value B"))
		assert.NotEqual(t, a.Summary().Revision(), b.Summary().Revision(), kind)
	}
}

type externalCabBuffer struct{ bytes.Buffer }

func (b *externalCabBuffer) Close() error { return nil }

func TestPackageCodeCoversExternalCabinetPayload(t *testing.T) {
	makePackage := func(payload string) ([]byte, msi.Database, []byte) {
		b := authoringPackage(payload)
		cabinet := &externalCabBuffer{}
		b.WithExternalCabs(func(name string) (io.WriteCloser, error) { assert.Equal(t, "external.cab", name); return cabinet, nil })
		b.Media(1).WithCabinet("external.cab").External()
		data, db := authoredBytes(t, b)
		return data, db, cabinet.Bytes()
	}
	a, dbA, cabA := makePackage("PAYLOAD-A")
	repeated, dbSame, cabSame := makePackage("PAYLOAD-A")
	_, dbB, cabB := makePackage("PAYLOAD-B")
	assert.Equal(t, a, repeated)
	assert.Equal(t, cabA, cabSame)
	assert.Equal(t, dbA.Summary().Revision(), dbSame.Summary().Revision())
	assert.NotEqual(t, cabA, cabB)
	assert.NotEqual(t, dbA.Summary().Revision(), dbB.Summary().Revision())
}

func TestMinimalUIStandardMessageAndTerminalDialogs(t *testing.T) {
	_, db := authoredBytes(t, authoringPackage("base").WithMinimalUI())
	for _, table := range []string{"InstallUISequence", "AdminUISequence"} {
		rows, err := db.Table(table)
		require.NoError(t, err)
		seq := map[string]int16{}
		for _, row := range rows {
			seq[row["Action"].(string)] = row["Sequence"].(int16)
		}
		assert.Equal(t, int16(-1), seq["ExitDialog"], table)
		assert.Equal(t, int16(-2), seq["UserExit"], table)
		assert.Equal(t, int16(-3), seq["FatalError"], table)
	}
	rows, err := db.Table("Property")
	require.NoError(t, err)
	found := false
	for _, row := range rows {
		if row["Property"] == "ErrorDialog" {
			assert.Equal(t, "ErrorDlg", row["Value"])
			found = true
		}
	}
	assert.True(t, found)
	rows, err = db.Table("Dialog")
	require.NoError(t, err)
	for _, row := range rows {
		if row["Dialog"] == "ErrorDlg" {
			assert.NotZero(t, row["Attributes"].(int32)&int32(msi.DialogError))
			assert.Equal(t, "ErrorText", row["Control_First"])
		}
		if row["Dialog"] == "FatalError" {
			assert.Zero(t, row["Attributes"].(int32)&int32(msi.DialogError))
		}
	}
	rows, err = db.Table("ControlEvent")
	require.NoError(t, err)
	responses := map[string]string{}
	inUse := map[string]bool{}
	for _, row := range rows {
		if row["Dialog_"] == "ErrorDlg" {
			assert.Equal(t, "EndDialog", row["Event"])
			responses[row["Control_"].(string)] = row["Argument"].(string)
		}
		if row["Dialog_"] == "FilesInUse" {
			assert.Equal(t, "EndDialog", row["Event"])
			inUse[row["Argument"].(string)] = true
		}
	}
	assert.Equal(t, map[string]string{"A": "ErrorAbort", "C": "ErrorCancel", "I": "ErrorIgnore", "N": "ErrorNo", "O": "ErrorOk", "R": "ErrorRetry", "Y": "ErrorYes"}, responses)
	assert.Equal(t, map[string]bool{"Exit": true, "Ignore": true, "Retry": true}, inUse)
	assert.Contains(t, db.Tables(), "ListBox")
	rows, err = db.Table("Control")
	require.NoError(t, err)
	found = false
	for _, row := range rows {
		if row["Dialog_"] == "FilesInUse" && row["Type"] == "ListBox" {
			assert.Equal(t, "FileInUseProcess", row["Property"])
			found = true
		}
	}
	assert.True(t, found)
}

func TestShortNamesShareFileAndShortcutNamespace(t *testing.T) {
	for _, names := range [][2]string{{"abcdef1long.lnk", "abcdef2long.lnk"}, {"abcdef~1.lnk", "abcdef2long.lnk"}, {"abcdef1long.lnk", "ABCDEF~1.LNK"}} {
		for _, dot := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/%s/dot=%v", names[0], names[1], dot), func(t *testing.T) {
				b := authoringPackage("base")
				d := b.Directory("INSTALLFOLDER")
				c := d.Component("Sibling").AssociateToFeature("Main")
				c.WithFile(names[0], msi.FileSourceFromBytes([]byte("distinct payload")))
				dir := "INSTALLFOLDER"
				if dot {
					d.Subdirectory("Dot", ".")
					dir = "Dot"
				}
				c.Shortcut(names[1], "[INSTALLFOLDER]payload.txt").InDirectory(dir)
				_, db := authoredBytes(t, b)
				files, err := db.Table("File")
				require.NoError(t, err)
				shortcuts, err := db.Table("Shortcut")
				require.NoError(t, err)
				require.Len(t, shortcuts, 1)
				alias := strings.ToUpper(strings.Split(shortcuts[0]["Name"].(string), "|")[0])
				for _, row := range files {
					assert.NotEqual(t, alias, strings.ToUpper(strings.Split(row["FileName"].(string), "|")[0]))
				}
			})
		}
	}
}

func TestModelessProgressSpawnsModalCancelConfirmation(t *testing.T) {
	_, db := authoredBytes(t, authoringPackage("base").WithMinimalUI())
	rows, err := db.Table("Dialog")
	require.NoError(t, err)
	found := false
	for _, row := range rows {
		if row["Dialog"] == "CancelDlg" {
			assert.NotZero(t, row["Attributes"].(int32)&int32(msi.DialogModal))
			found = true
		}
	}
	assert.True(t, found)
	rows, err = db.Table("ControlEvent")
	require.NoError(t, err)
	events := map[string]string{}
	progressCancel := false
	for _, row := range rows {
		dialog, control := row["Dialog_"].(string), row["Control_"].(string)
		if dialog == "ProgressDlg" && control == "Cancel" {
			assert.Equal(t, "SpawnDialog", row["Event"])
			assert.Equal(t, "CancelDlg", row["Argument"])
			progressCancel = true
		}
		if dialog == "CancelDlg" {
			assert.Equal(t, "EndDialog", row["Event"])
			events[control] = row["Argument"].(string)
		}
	}
	assert.True(t, progressCancel)
	assert.Equal(t, map[string]string{"Yes": "Exit", "No": "Return"}, events)
}

func TestShortcutNameValidationUsesFilenameCategory(t *testing.T) {
	b := authoringPackage("base")
	b.Directory("INSTALLFOLDER").Component("Payload").Shortcut("abcdef2long.lnk", "Main").Advertised("Main")
	_, db := authoredBytes(t, b)
	rows, err := db.Table("_Validation")
	require.NoError(t, err)
	found := false
	for _, row := range rows {
		if row["Table"] == "Shortcut" && row["Column"] == "Name" {
			assert.Equal(t, "Filename", row["Category"])
			found = true
		}
	}
	assert.True(t, found)
}
