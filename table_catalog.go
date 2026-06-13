package msi

// msi_table_catalog.go
// Canonical, data-only schema definitions for the standard Windows Installer
// tables emitted by this package, including the _Validation metadata for
// every column.
//
// Provenance: transcribed facts from the Microsoft Learn per-table docs
// (https://learn.microsoft.com/en-us/windows/win32/msi/<page>):
//   property-table, directory-table, component-table, feature-table,
//   featurecomponents-table, file-table, media-table,
//   installexecutesequence-table, installuisequence-table,
//   adminexecutesequence-table, adminuisequence-table,
//   advtexecutesequence-table, -validation-table
// cross-checked against the machine-readable MSI SDK schema shipped with
// WiX v3 (tables.xml). Column type bitfields are produced from these
// definitions by msiColumn.typeBits() (Wine msipriv.h / sql.y; rust-msi
// column.rs).
//
// Deliberate choices where sources differ:
//   - File.Sequence and Media.LastSequence are i2 (Integer, max 32767) per
//     Microsoft Learn; WiX v3 widens them to i4. The schema is
//     self-describing via _Columns, so readers accept either; i2 matches the
//     int16 values this package already writes.
//   - GUID columns use the category spelling "Guid" (WiX/MSI SDK) rather
//     than rust-msi's "GUID".
//   - Condition columns are LOCALIZABLE (L255) following WiX and real-world
//     MSIs; Microsoft Learn does not state localizability.

// msiCatalogColumn describes one column of a canonical MSI table: its schema
// (1-based position, internal category, declared width, key / nullable /
// localizable flags) plus the content of its _Validation row (min/max range,
// foreign key target, category, permitted set, description). nil pointer and
// "" string fields mean NULL in the corresponding _Validation cell.
type msiCatalogColumn struct {
	name        string
	position    int
	colType     msiColumnType
	width       int
	key         bool
	nullable    bool
	localizable bool
	minValue    *int32
	maxValue    *int32
	keyTable    string
	keyColumn   *int16
	category    string
	set         string
	description string
}

// msiCatalogTableDef is the canonical definition of one MSI table.
type msiCatalogTableDef struct {
	name    string
	columns []msiCatalogColumn
}

func msiCatInt32(v int32) *int32 { return &v }
func msiCatInt16(v int16) *int16 { return &v }

// msiSequenceTableCatalogDef returns the shared schema of the five standard
// sequence tables (InstallExecuteSequence, InstallUISequence,
// AdminExecuteSequence, AdminUISequence, AdvtExecuteSequence); all five are
// identical in the MSI SDK.
// moduleSeqCatalogDef defines a merge-module sequence table (Module*Sequence):
// like a standard sequence table but with BaseAction/After columns that splice
// the module's action relative to a base action when merged. Action is the only
// key in our catalog (keys-first; exact PK fidelity is not needed for tables
// go-msix never emits — they exist only so ICE03 can validate them).
func moduleSeqCatalogDef(name string) msiCatalogTableDef {
	return msiCatalogTableDef{
		name: name,
		columns: []msiCatalogColumn{
			{name: "Action", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "The action to splice into the base sequence."},
			{name: "Sequence", position: 2, colType: msiColInteger, width: 2, nullable: true, minValue: msiCatInt32(-4), maxValue: msiCatInt32(32767), category: "Integer", description: "Absolute sequence number (mutually exclusive with BaseAction/After)."},
			{name: "BaseAction", position: 3, colType: msiColIdentifier, width: 72, nullable: true, category: "Identifier", description: "The base action to splice relative to."},
			{name: "After", position: 4, colType: msiColInteger, width: 2, nullable: true, minValue: msiCatInt32(0), maxValue: msiCatInt32(1), category: "Integer", description: "0 = before BaseAction, 1 = after."},
			{name: "Condition", position: 5, colType: msiColCondition, width: 255, nullable: true, category: "Condition", description: "Optional condition."},
		},
	}
}

func msiSequenceTableCatalogDef(name string) msiCatalogTableDef {
	return msiCatalogTableDef{
		name: name,
		columns: []msiCatalogColumn{
			{
				name: "Action", position: 1, colType: msiColIdentifier, width: 72, key: true,
				category:    "Identifier",
				description: "Name of action to invoke, either in the engine or the handler DLL.",
			},
			{
				name: "Condition", position: 2, colType: msiColCondition, width: 255, nullable: true, localizable: true,
				category:    "Condition",
				description: "Optional expression which skips the action if evaluates to expFalse.If the expression syntax is invalid, the engine will terminate, returning iesBadActionData.",
			},
			{
				name: "Sequence", position: 3, colType: msiColInteger, width: 2, nullable: true,
				minValue: msiCatInt32(-4), maxValue: msiCatInt32(32767),
				description: "Number that determines the sort order in which the actions are to be executed.  Leave blank to suppress action.",
			},
		},
	}
}

// msiTableCatalog holds every canonical table definition in a fixed,
// deterministic order. It is initialized once and must never be mutated.
var msiTableCatalog = []msiCatalogTableDef{
	{
		name: msiPropTableName,
		columns: []msiCatalogColumn{
			{
				name: "Property", position: 1, colType: msiColIdentifier, width: 72, key: true,
				category:    "Identifier",
				description: "Name of property, uppercase if settable by launcher or loader.",
			},
			{
				name: "Value", position: 2, colType: msiColText, width: 0, localizable: true,
				category:    "Text",
				description: "String value for property. Never null or empty.",
			},
		},
	},
	{
		name: msiDirTableName,
		columns: []msiCatalogColumn{
			{
				name: "Directory", position: 1, colType: msiColIdentifier, width: 72, key: true,
				category:    "Identifier",
				description: "Unique identifier for directory entry, primary key. If a property by this name is defined, it contains the full path to the directory.",
			},
			{
				name: "Directory_Parent", position: 2, colType: msiColIdentifier, width: 72, nullable: true,
				keyTable: msiDirTableName, keyColumn: msiCatInt16(1),
				category:    "Identifier",
				description: "Reference to the entry in this table specifying the default parent directory. A record parented to itself or with a Null parent represents a root of the install tree.",
			},
			{
				name: "DefaultDir", position: 3, colType: msiColDefaultDir, width: 255, localizable: true,
				category:    "DefaultDir",
				description: "The default sub-path under parent's path.",
			},
		},
	},
	{
		name: msiCompTableName,
		columns: []msiCatalogColumn{
			{
				name: "Component", position: 1, colType: msiColIdentifier, width: 72, key: true,
				category:    "Identifier",
				description: "Primary key used to identify a particular component record.",
			},
			{
				name: "ComponentId", position: 2, colType: msiColGUID, width: 38, nullable: true,
				category:    "Guid",
				description: "A string GUID unique to this component, version, and language.",
			},
			{
				name: "Directory_", position: 3, colType: msiColIdentifier, width: 72,
				keyTable: msiDirTableName, keyColumn: msiCatInt16(1),
				category:    "Identifier",
				description: "Required key of a Directory table record. This is actually a property name whose value contains the actual path, set either by the AppSearch action or with the default setting obtained from the Directory table.",
			},
			{
				name: "Attributes", position: 4, colType: msiColInteger, width: 2,
				description: "Remote execution option, one of irsEnum",
			},
			{
				name: "Condition", position: 5, colType: msiColCondition, width: 255, nullable: true, localizable: true,
				category:    "Condition",
				description: "A conditional statement that will disable this component if the specified condition evaluates to the 'True' state. If a component is disabled, it will not be installed, regardless of the 'Action' state associated with the component.",
			},
			{
				name: "KeyPath", position: 6, colType: msiColIdentifier, width: 72, nullable: true,
				keyTable: "File;Registry;ODBCDataSource", keyColumn: msiCatInt16(1),
				category:    "Identifier",
				description: "Either the primary key into the File table, Registry table, or ODBCDataSource table. This extract path is stored when the component is installed, and is used to detect the presence of the component and to return the path to it.",
			},
		},
	},
	{
		name: msiFeatTableName,
		columns: []msiCatalogColumn{
			{
				name: "Feature", position: 1, colType: msiColIdentifier, width: 38, key: true,
				category:    "Identifier",
				description: "Primary key used to identify a particular feature record.",
			},
			{
				name: "Feature_Parent", position: 2, colType: msiColIdentifier, width: 38, nullable: true,
				keyTable: msiFeatTableName, keyColumn: msiCatInt16(1),
				category:    "Identifier",
				description: "Optional key of a parent record in the same table. If the parent is not selected, then the record will not be installed. Null indicates a root item.",
			},
			{
				name: "Title", position: 3, colType: msiColText, width: 64, nullable: true, localizable: true,
				category:    "Text",
				description: "Short text identifying a visible feature item.",
			},
			{
				name: "Description", position: 4, colType: msiColText, width: 255, nullable: true, localizable: true,
				category:    "Text",
				description: "Longer descriptive text describing a visible feature item.",
			},
			{
				name: "Display", position: 5, colType: msiColInteger, width: 2, nullable: true,
				minValue: msiCatInt32(0), maxValue: msiCatInt32(32767),
				description: "Numeric sort order, used to force a specific display ordering.",
			},
			{
				name: "Level", position: 6, colType: msiColInteger, width: 2,
				minValue: msiCatInt32(0), maxValue: msiCatInt32(32767),
				description: "The install level at which record will be initially selected. An install level of 0 will disable an item and prevent its display.",
			},
			{
				name: "Directory_", position: 7, colType: msiColUpperCase, width: 72, nullable: true,
				keyTable: msiDirTableName, keyColumn: msiCatInt16(1),
				category:    "UpperCase",
				description: "The name of the Directory that can be configured by the UI. A non-null value will enable the browse button.",
			},
			{
				name: "Attributes", position: 8, colType: msiColInteger, width: 2,
				set:         "0;1;2;4;5;6;8;9;10;16;17;18;20;21;22;24;25;26;32;33;34;36;37;38;48;49;50;52;53;54",
				description: "Feature attributes",
			},
		},
	},
	{
		name: msiFeatCompTableName,
		columns: []msiCatalogColumn{
			{
				name: "Feature_", position: 1, colType: msiColIdentifier, width: 38, key: true,
				keyTable: msiFeatTableName, keyColumn: msiCatInt16(1),
				category:    "Identifier",
				description: "Foreign key into Feature table.",
			},
			{
				name: "Component_", position: 2, colType: msiColIdentifier, width: 72, key: true,
				keyTable: msiCompTableName, keyColumn: msiCatInt16(1),
				category:    "Identifier",
				description: "Foreign key into Component table.",
			},
		},
	},
	{
		name: msiFileTableName,
		columns: []msiCatalogColumn{
			{
				name: "File", position: 1, colType: msiColIdentifier, width: 72, key: true,
				category:    "Identifier",
				description: "Primary key, non-localized token, must match identifier in cabinet. For uncompressed files, this field is ignored.",
			},
			{
				name: "Component_", position: 2, colType: msiColIdentifier, width: 72,
				keyTable: msiCompTableName, keyColumn: msiCatInt16(1),
				category:    "Identifier",
				description: "Foreign key referencing Component that controls the file.",
			},
			{
				name: "FileName", position: 3, colType: msiColFilename, width: 255, localizable: true,
				category:    "Filename",
				description: "File name used for installation, may be localized. This may contain a \"short name|long name\" pair.",
			},
			{
				name: "FileSize", position: 4, colType: msiColDoubleInteger, width: 4,
				minValue: msiCatInt32(0), maxValue: msiCatInt32(2147483647),
				description: "Size of file in bytes (long integer).",
			},
			{
				name: "Version", position: 5, colType: msiColVersion, width: 72, nullable: true,
				keyTable: msiFileTableName, keyColumn: msiCatInt16(1),
				category:    "Version",
				description: "Version string for versioned files; Blank for unversioned files.",
			},
			{
				name: "Language", position: 6, colType: msiColLanguage, width: 20, nullable: true,
				category:    "Language",
				description: "List of decimal language Ids, comma-separated if more than one.",
			},
			{
				name: "Attributes", position: 7, colType: msiColInteger, width: 2, nullable: true,
				minValue: msiCatInt32(0), maxValue: msiCatInt32(32767),
				description: "Integer containing bit flags representing file attributes (with the decimal value of each bit position in parentheses)",
			},
			{
				name: "Sequence", position: 8, colType: msiColInteger, width: 2,
				minValue: msiCatInt32(1), maxValue: msiCatInt32(32767),
				description: "Sequence with respect to the media images; order must track cabinet order.",
			},
		},
	},
	{
		name: msiMediaTableName,
		columns: []msiCatalogColumn{
			{
				name: "DiskId", position: 1, colType: msiColInteger, width: 2, key: true,
				minValue: msiCatInt32(1), maxValue: msiCatInt32(32767),
				description: "Primary key, integer to determine sort order for table.",
			},
			{
				name: "LastSequence", position: 2, colType: msiColInteger, width: 2,
				minValue: msiCatInt32(0), maxValue: msiCatInt32(32767),
				description: "File sequence number for the last file for this media.",
			},
			{
				name: "DiskPrompt", position: 3, colType: msiColText, width: 64, nullable: true, localizable: true,
				category:    "Text",
				description: "Disk name: the visible text actually printed on the disk. This will be used to prompt the user when this disk needs to be inserted.",
			},
			{
				name: "Cabinet", position: 4, colType: msiColCabinet, width: 255, nullable: true,
				category:    "Cabinet",
				description: "If some or all of the files stored on the media are compressed in a cabinet, the name of that cabinet.",
			},
			{
				name: "VolumeLabel", position: 5, colType: msiColText, width: 32, nullable: true,
				category:    "Text",
				description: "The label attributed to the volume.",
			},
			{
				name: "Source", position: 6, colType: msiColProperty, width: 72, nullable: true,
				category:    "Property",
				description: "The property defining the location of the cabinet file.",
			},
		},
	},
	msiSequenceTableCatalogDef(msiInstallExecSeqTableName),
	msiSequenceTableCatalogDef(msiInstallUISeqTableName),
	msiSequenceTableCatalogDef(msiAdminExecSeqTableName),
	msiSequenceTableCatalogDef(msiAdminUISeqTableName),
	msiSequenceTableCatalogDef(msiAdvtExecSeqTableName),
	{
		name: msiValidationTableName,
		columns: []msiCatalogColumn{
			{
				name: "Table", position: 1, colType: msiColIdentifier, width: 32, key: true,
				category:    "Identifier",
				description: "Name of table",
			},
			{
				name: "Column", position: 2, colType: msiColIdentifier, width: 32, key: true,
				category:    "Identifier",
				description: "Name of column",
			},
			{
				name: "Nullable", position: 3, colType: msiColText, width: 4,
				set:         "Y;N",
				description: "Whether the column is nullable",
			},
			{
				name: "MinValue", position: 4, colType: msiColDoubleInteger, width: 4, nullable: true,
				minValue: msiCatInt32(-2147483647), maxValue: msiCatInt32(2147483647),
				description: "Minimum value allowed",
			},
			{
				name: "MaxValue", position: 5, colType: msiColDoubleInteger, width: 4, nullable: true,
				minValue: msiCatInt32(-2147483647), maxValue: msiCatInt32(2147483647),
				description: "Maximum value allowed",
			},
			{
				name: "KeyTable", position: 6, colType: msiColIdentifier, width: 255, nullable: true,
				category:    "Identifier",
				description: "For foreign key, Name of table to which data must link",
			},
			{
				name: "KeyColumn", position: 7, colType: msiColInteger, width: 2, nullable: true,
				minValue: msiCatInt32(1), maxValue: msiCatInt32(32),
				description: "Column to which foreign key connects",
			},
			{
				name: "Category", position: 8, colType: msiColText, width: 32, nullable: true,
				set:         "Text;Formatted;Template;Condition;Guid;Path;Version;Language;Identifier;Binary;UpperCase;LowerCase;Filename;Paths;AnyPath;WildCardFilename;RegPath;CustomSource;Property;Cabinet;Shortcut;FormattedSDDLText;Integer;DoubleInteger;TimeDate;DefaultDir",
				description: "String category",
			},
			{
				name: "Set", position: 9, colType: msiColText, width: 255, nullable: true,
				category:    "Text",
				description: "Set of values that are permitted",
			},
			{
				name: "Description", position: 10, colType: msiColText, width: 255, nullable: true,
				category:    "Text",
				description: "Description of column",
			},
		},
	},
	// Minimal defs for P3 tables (transcribed from MSDN for emitted columns; full in future).
	{
		name: "Registry",
		columns: []msiCatalogColumn{
			{name: "Registry", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Primary key, non-localized token"},
			{name: "Root", position: 2, colType: msiColInteger, width: 2, key: true, category: "Integer", description: "Root key; 0=HKCR, 1=HKCU, 2=HKLM, 3=HKU, -1=HKMU"},
			{name: "Key", position: 3, colType: msiColRegPath, width: 255, category: "RegPath", description: "Registry key (relative to Root)"},
			{name: "Name", position: 4, colType: msiColText, width: 255, nullable: true, category: "Text", description: "Registry value name (or null for default)"},
			{name: "Value", position: 5, colType: msiColText, width: 255, nullable: true, category: "Text", description: "Registry value (formatted, # for dword etc.)"},
			{name: "Component_", position: 6, colType: msiColIdentifier, width: 72, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1), description: "Foreign key into Component table"},
		},
	},
	{
		name: "Shortcut",
		columns: []msiCatalogColumn{
			{name: "Shortcut", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier"},
			{name: "Directory_", position: 2, colType: msiColIdentifier, width: 72, category: "Identifier", keyTable: "Directory", keyColumn: msiCatInt16(1)},
			{name: "Name", position: 3, colType: msiColShortcut, width: 128, category: "Shortcut"},
			{name: "Component_", position: 4, colType: msiColIdentifier, width: 72, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1)},
			{name: "Target", position: 5, colType: msiColText, width: 255, nullable: true, category: "Text"},
			{name: "Arguments", position: 6, colType: msiColText, width: 255, nullable: true, category: "Text"},
			{name: "Description", position: 7, colType: msiColText, width: 255, nullable: true, category: "Text"},
			{name: "Hotkey", position: 8, colType: msiColInteger, width: 2, nullable: true, category: "Integer"},
			{name: "Icon_", position: 9, colType: msiColIdentifier, width: 72, nullable: true, category: "Identifier"},
			{name: "IconIndex", position: 10, colType: msiColInteger, width: 2, nullable: true, category: "Integer"},
			{name: "ShowCmd", position: 11, colType: msiColInteger, width: 2, nullable: true, category: "Integer"},
			{name: "WkDir", position: 12, colType: msiColText, width: 255, nullable: true, category: "Text"},
		},
	},
	{
		name: "Icon",
		columns: []msiCatalogColumn{
			{name: "Name", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Name of the icon (primary key)"},
			{name: "Data", position: 2, colType: msiColBinary, width: 0, category: "Binary", description: "Binary icon data"},
		},
	},
	{
		name: "Binary",
		columns: []msiCatalogColumn{
			{name: "Name", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Name of the binary data (primary key)"},
			{name: "Data", position: 2, colType: msiColBinary, width: 0, category: "Binary", description: "Binary data"},
		},
	},
	{
		name: "MsiFileHash",
		columns: []msiCatalogColumn{
			{name: "File_", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "File", keyColumn: msiCatInt16(1), description: "Foreign key into File table"},
			{name: "Options", position: 2, colType: msiColInteger, width: 2, key: true, category: "Integer", description: "Hash options (0 for MD5)"},
			{name: "HashPart1", position: 3, colType: msiColDoubleInteger, width: 4, category: "DoubleInteger", description: "First 32 bits of MD5 hash"},
			{name: "HashPart2", position: 4, colType: msiColDoubleInteger, width: 4, category: "DoubleInteger", description: "Second 32 bits of MD5 hash"},
			{name: "HashPart3", position: 5, colType: msiColDoubleInteger, width: 4, category: "DoubleInteger", description: "Third 32 bits of MD5 hash"},
			{name: "HashPart4", position: 6, colType: msiColDoubleInteger, width: 4, category: "DoubleInteger", description: "Fourth 32 bits of MD5 hash"},
		},
	},
	{
		name: "RemoveRegistry",
		columns: []msiCatalogColumn{
			{name: "RemoveRegistry", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier"},
			{name: "Root", position: 2, colType: msiColInteger, width: 2, key: true, category: "Integer"},
			{name: "Key", position: 3, colType: msiColRegPath, width: 255, category: "RegPath"},
			{name: "Name", position: 4, colType: msiColText, width: 255, nullable: true, category: "Text"},
			{name: "Component_", position: 5, colType: msiColIdentifier, width: 72, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1)},
		},
	},
	{
		name: "RemoveFile",
		columns: []msiCatalogColumn{
			{name: "FileKey", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier"},
			{name: "Component_", position: 2, colType: msiColIdentifier, width: 72, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1)},
			{name: "FileName", position: 3, colType: msiColText, width: 255, nullable: true, category: "Text"},
			{name: "DirProperty", position: 4, colType: msiColIdentifier, width: 72, nullable: true, category: "Identifier"},
			{name: "InstallMode", position: 5, colType: msiColInteger, width: 2, nullable: true, category: "Integer"},
		},
	},
	{
		name: "CreateFolder",
		columns: []msiCatalogColumn{
			{name: "Component_", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1)},
			{name: "Directory_", position: 2, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "Directory", keyColumn: msiCatInt16(1)},
		},
	},
	{
		name: "Environment",
		columns: []msiCatalogColumn{
			{name: "Environment", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier"},
			{name: "Name", position: 2, colType: msiColText, width: 255, category: "Text"},
			{name: "Value", position: 3, colType: msiColText, width: 255, nullable: true, category: "Text"},
			{name: "Component_", position: 4, colType: msiColIdentifier, width: 72, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1)},
		},
	},

	// P4 — Services. ServiceType/StartType/ErrorControl are DoubleInteger (i4)
	// per Microsoft Learn (the 64-bit-safe width matched by msidump); cells are
	// int32. Name/DisplayName/StartName/etc. are Formatted. Description is
	// Formatted, nullable (MS Learn), not localizable text.
	{
		name: "ServiceInstall",
		columns: []msiCatalogColumn{
			{name: "ServiceInstall", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Primary key"},
			{name: "Name", position: 2, colType: msiColFormatted, width: 255, category: "Formatted", description: "Service name"},
			{name: "DisplayName", position: 3, colType: msiColFormatted, width: 255, nullable: true, category: "Formatted", description: "Localizable display name"},
			{name: "ServiceType", position: 4, colType: msiColDoubleInteger, width: 4, category: "DoubleInteger", description: "Service type bit flags"},
			{name: "StartType", position: 5, colType: msiColDoubleInteger, width: 4, category: "DoubleInteger", description: "Service start type"},
			{name: "ErrorControl", position: 6, colType: msiColDoubleInteger, width: 4, category: "DoubleInteger", description: "Error control level (high bit = vital)"},
			{name: "LoadOrderGroup", position: 7, colType: msiColFormatted, width: 255, nullable: true, category: "Formatted"},
			{name: "Dependencies", position: 8, colType: msiColFormatted, width: 255, nullable: true, category: "Formatted", description: "[~]-separated dependency list"},
			{name: "StartName", position: 9, colType: msiColFormatted, width: 255, nullable: true, category: "Formatted"},
			{name: "Password", position: 10, colType: msiColFormatted, width: 255, nullable: true, category: "Formatted"},
			{name: "Arguments", position: 11, colType: msiColFormatted, width: 255, nullable: true, category: "Formatted"},
			{name: "Component_", position: 12, colType: msiColIdentifier, width: 72, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1)},
			{name: "Description", position: 13, colType: msiColFormatted, width: 255, nullable: true, category: "Formatted"},
		},
	},
	{
		name: "ServiceControl",
		columns: []msiCatalogColumn{
			{name: "ServiceControl", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Primary key"},
			{name: "Name", position: 2, colType: msiColFormatted, width: 255, category: "Formatted", description: "Service name to control"},
			{name: "Event", position: 3, colType: msiColInteger, width: 2, category: "Integer", description: "Control event bit flags"},
			{name: "Arguments", position: 4, colType: msiColFormatted, width: 255, nullable: true, category: "Formatted"},
			{name: "Wait", position: 5, colType: msiColInteger, width: 2, nullable: true, category: "Integer", description: "0=do not wait, 1=wait"},
			{name: "Component_", position: 6, colType: msiColIdentifier, width: 72, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1)},
		},
	},
	{
		name: "MsiServiceConfig",
		columns: []msiCatalogColumn{
			{name: "MsiServiceConfig", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Primary key"},
			{name: "Name", position: 2, colType: msiColFormatted, width: 255, category: "Formatted", description: "Service name"},
			{name: "Event", position: 3, colType: msiColInteger, width: 2, category: "Integer", description: "Install/uninstall event bits"},
			{name: "ConfigType", position: 4, colType: msiColInteger, width: 2, category: "Integer", description: "SERVICE_CONFIG_* type"},
			{name: "Argument", position: 5, colType: msiColFormatted, width: 255, nullable: true, category: "Formatted"},
			{name: "Component_", position: 6, colType: msiColIdentifier, width: 72, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1)},
		},
	},
	{
		name: "MsiServiceConfigFailureActions",
		columns: []msiCatalogColumn{
			{name: "MsiServiceConfigFailureActions", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Primary key"},
			{name: "Name", position: 2, colType: msiColFormatted, width: 255, category: "Formatted", description: "Service name"},
			{name: "Event", position: 3, colType: msiColInteger, width: 2, category: "Integer"},
			{name: "ResetPeriod", position: 4, colType: msiColDoubleInteger, width: 4, nullable: true, category: "DoubleInteger", description: "Failure-count reset period (seconds)"},
			{name: "RebootMessage", position: 5, colType: msiColFormatted, width: 255, nullable: true, category: "Formatted"},
			{name: "Command", position: 6, colType: msiColFormatted, width: 255, nullable: true, category: "Formatted"},
			{name: "Actions", position: 7, colType: msiColText, width: 255, nullable: true, category: "Text", description: "[~]-separated SC_ACTION types"},
			{name: "DelayActions", position: 8, colType: msiColText, width: 255, nullable: true, category: "Text", description: "[~]-separated delays (ms)"},
			{name: "Component_", position: 9, colType: msiColIdentifier, width: 72, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1)},
		},
	},

	// P4 — Upgrades and launch conditions. Upgrade has a composite primary key
	// across columns 1-5. Attributes is DoubleInteger (i4). ActionProperty must
	// be an UpperCase public property (it is referenced from SecureCustomProperties).
	{
		name: "Upgrade",
		columns: []msiCatalogColumn{
			{name: "UpgradeCode", position: 1, colType: msiColGUID, width: 38, key: true, category: "Guid", description: "Related-product UpgradeCode"},
			{name: "VersionMin", position: 2, colType: msiColText, width: 20, key: true, nullable: true, category: "Text", description: "Minimum version detected"},
			{name: "VersionMax", position: 3, colType: msiColText, width: 20, key: true, nullable: true, category: "Text", description: "Maximum version detected"},
			{name: "Language", position: 4, colType: msiColLanguage, width: 255, key: true, nullable: true, category: "Language"},
			{name: "Attributes", position: 5, colType: msiColDoubleInteger, width: 4, key: true, category: "DoubleInteger", minValue: msiCatInt32(0), maxValue: msiCatInt32(2147483647), description: "Upgrade attribute bit flags"},
			{name: "Remove", position: 6, colType: msiColFormatted, width: 255, nullable: true, category: "Formatted", description: "Features to remove (NULL = all)"},
			{name: "ActionProperty", position: 7, colType: msiColUpperCase, width: 72, category: "UpperCase", description: "Public property set to the detected ProductCode list"},
		},
	},
	{
		name: "LaunchCondition",
		columns: []msiCatalogColumn{
			{name: "Condition", position: 1, colType: msiColCondition, width: 255, key: true, category: "Condition", description: "Condition that must be satisfied"},
			{name: "Description", position: 2, colType: msiColFormatted, width: 255, localizable: true, category: "Formatted", description: "Message shown when the condition fails"},
		},
	},

	// P4 — AppSearch / file-signature search subsystem. AppSearch.Signature_
	// may reference either a Signature row or a *Locator row (shared key
	// namespace), so its KeyTable is the union of those tables.
	{
		name: "Signature",
		columns: []msiCatalogColumn{
			{name: "Signature", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Primary key"},
			{name: "FileName", position: 2, colType: msiColText, width: 255, category: "Text", description: "File name to match"},
			{name: "MinVersion", position: 3, colType: msiColText, width: 20, nullable: true, category: "Text"},
			{name: "MaxVersion", position: 4, colType: msiColText, width: 20, nullable: true, category: "Text"},
			{name: "MinSize", position: 5, colType: msiColDoubleInteger, width: 4, nullable: true, category: "DoubleInteger", minValue: msiCatInt32(0)},
			{name: "MaxSize", position: 6, colType: msiColDoubleInteger, width: 4, nullable: true, category: "DoubleInteger", minValue: msiCatInt32(0)},
			{name: "MinDate", position: 7, colType: msiColDoubleInteger, width: 4, nullable: true, category: "DoubleInteger", minValue: msiCatInt32(0)},
			{name: "MaxDate", position: 8, colType: msiColDoubleInteger, width: 4, nullable: true, category: "DoubleInteger", minValue: msiCatInt32(0)},
			{name: "Languages", position: 9, colType: msiColLanguage, width: 255, nullable: true, category: "Language"},
		},
	},
	{
		name: "AppSearch",
		columns: []msiCatalogColumn{
			{name: "Property", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Property set to the search result"},
			{name: "Signature_", position: 2, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "Signature;RegLocator;IniLocator;CompLocator;DrLocator", keyColumn: msiCatInt16(1), description: "Signature or locator key"},
		},
	},
	{
		name: "RegLocator",
		columns: []msiCatalogColumn{
			{name: "Signature_", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Primary key / Signature link"},
			{name: "Root", position: 2, colType: msiColInteger, width: 2, category: "Integer", description: "Registry root (0=HKCR,1=HKCU,2=HKLM,3=HKU)"},
			{name: "Key", position: 3, colType: msiColRegPath, width: 255, category: "RegPath"},
			{name: "Name", position: 4, colType: msiColFormatted, width: 255, nullable: true, category: "Formatted"},
			{name: "Type", position: 5, colType: msiColInteger, width: 2, nullable: true, category: "Integer", description: "0=directory,1=file,2=raw value (+0x10 64-bit)"},
		},
	},
	{
		name: "IniLocator",
		columns: []msiCatalogColumn{
			{name: "Signature_", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier"},
			{name: "FileName", position: 2, colType: msiColText, width: 255, category: "Text"},
			{name: "Section", position: 3, colType: msiColText, width: 96, category: "Text"},
			{name: "Key", position: 4, colType: msiColText, width: 128, category: "Text"},
			{name: "Field", position: 5, colType: msiColInteger, width: 2, nullable: true, category: "Integer", minValue: msiCatInt32(0)},
			{name: "Type", position: 6, colType: msiColInteger, width: 2, nullable: true, category: "Integer", description: "0=directory,1=file,2=raw value"},
		},
	},
	{
		name: "CompLocator",
		columns: []msiCatalogColumn{
			{name: "Signature_", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier"},
			{name: "ComponentId", position: 2, colType: msiColGUID, width: 38, category: "Guid"},
			{name: "Type", position: 3, colType: msiColInteger, width: 2, nullable: true, category: "Integer", description: "0=directory,1=file"},
		},
	},
	{
		name: "DrLocator",
		columns: []msiCatalogColumn{
			{name: "Signature_", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier"},
			{name: "Parent", position: 2, colType: msiColIdentifier, width: 72, key: true, nullable: true, category: "Identifier", description: "Parent signature/locator key"},
			{name: "Path", position: 3, colType: msiColAnyPath, width: 255, key: true, nullable: true, category: "AnyPath"},
			{name: "Depth", position: 4, colType: msiColInteger, width: 2, nullable: true, category: "Integer", minValue: msiCatInt32(0)},
		},
	},

	// P4 — Error and ActionText (stock messages / progress text). Added for
	// completeness; Error.Message and ActionText.* are localizable templates.
	{
		name: "Error",
		columns: []msiCatalogColumn{
			{name: "Error", position: 1, colType: msiColInteger, width: 2, key: true, category: "Integer", minValue: msiCatInt32(0), maxValue: msiCatInt32(32767), description: "Error number (primary key)"},
			{name: "Message", position: 2, colType: msiColTemplate, width: 0, nullable: true, localizable: true, category: "Template"},
		},
	},
	{
		name: "ActionText",
		columns: []msiCatalogColumn{
			{name: "Action", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Action name (primary key)"},
			{name: "Description", position: 2, colType: msiColText, width: 255, nullable: true, localizable: true, category: "Text"},
			{name: "Template", position: 3, colType: msiColTemplate, width: 255, nullable: true, localizable: true, category: "Template"},
		},
	},

	// P5 — CustomAction. Type is the i2 base-type-plus-modifier bit field;
	// Source is a CustomSource key (Binary/File/Directory/Property name, per
	// type), Target is the Formatted entry-point/command-line/value/script.
	{
		name: "CustomAction",
		columns: []msiCatalogColumn{
			{name: "Action", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Primary key"},
			{name: "Type", position: 2, colType: msiColInteger, width: 2, category: "Integer", description: "Custom action type (base type | modifier bits)"},
			{name: "Source", position: 3, colType: msiColCustomSource, width: 72, nullable: true, category: "CustomSource", description: "Binary/File/Directory/Property key per type"},
			{name: "Target", position: 4, colType: msiColFormatted, width: 255, nullable: true, category: "Formatted", description: "Entry point / command line / value / script"},
			{name: "ExtendedType", position: 5, colType: msiColDoubleInteger, width: 4, nullable: true, category: "DoubleInteger", description: "Extended type info (NULL unless used)"},
		},
	},

	// P6 — UI tables. Dialog and EventMapping schemas are from Microsoft Learn
	// (absent from the sibling repo); the rest port from the sibling. Attributes
	// columns that can exceed int16 (0x10000, 0x80000 …) are DoubleInteger (i4).
	{
		name: "Dialog",
		columns: []msiCatalogColumn{
			{name: "Dialog", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Primary key"},
			{name: "HCentering", position: 2, colType: msiColInteger, width: 2, category: "Integer", minValue: msiCatInt32(0), maxValue: msiCatInt32(100), description: "Horizontal position 0-100"},
			{name: "VCentering", position: 3, colType: msiColInteger, width: 2, category: "Integer", minValue: msiCatInt32(0), maxValue: msiCatInt32(100), description: "Vertical position 0-100"},
			{name: "Width", position: 4, colType: msiColInteger, width: 2, category: "Integer", minValue: msiCatInt32(0)},
			{name: "Height", position: 5, colType: msiColInteger, width: 2, category: "Integer", minValue: msiCatInt32(0)},
			{name: "Attributes", position: 6, colType: msiColDoubleInteger, width: 4, nullable: true, category: "DoubleInteger", description: "Dialog style bit field"},
			{name: "Title", position: 7, colType: msiColFormatted, width: 128, nullable: true, localizable: true, category: "Formatted"},
			{name: "Control_First", position: 8, colType: msiColIdentifier, width: 50, category: "Identifier", description: "First control in tab order"},
			{name: "Control_Default", position: 9, colType: msiColIdentifier, width: 50, nullable: true, category: "Identifier"},
			{name: "Control_Cancel", position: 10, colType: msiColIdentifier, width: 50, nullable: true, category: "Identifier"},
		},
	},
	{
		name: "Control",
		columns: []msiCatalogColumn{
			{name: "Dialog_", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "Dialog", keyColumn: msiCatInt16(1)},
			{name: "Control", position: 2, colType: msiColIdentifier, width: 50, key: true, category: "Identifier"},
			{name: "Type", position: 3, colType: msiColIdentifier, width: 20, category: "Identifier", description: "Control type string"},
			{name: "X", position: 4, colType: msiColInteger, width: 2, category: "Integer", minValue: msiCatInt32(0)},
			{name: "Y", position: 5, colType: msiColInteger, width: 2, category: "Integer", minValue: msiCatInt32(0)},
			{name: "Width", position: 6, colType: msiColInteger, width: 2, category: "Integer", minValue: msiCatInt32(0)},
			{name: "Height", position: 7, colType: msiColInteger, width: 2, category: "Integer", minValue: msiCatInt32(0)},
			{name: "Attributes", position: 8, colType: msiColDoubleInteger, width: 4, nullable: true, category: "DoubleInteger", description: "Control attribute bit field"},
			{name: "Property", position: 9, colType: msiColIdentifier, width: 72, nullable: true, category: "Identifier"},
			{name: "Text", position: 10, colType: msiColFormatted, width: 0, nullable: true, localizable: true, category: "Formatted"},
			{name: "Control_Next", position: 11, colType: msiColIdentifier, width: 50, nullable: true, category: "Identifier", description: "Next control in tab order"},
			{name: "Help", position: 12, colType: msiColText, width: 50, nullable: true, localizable: true, category: "Text"},
		},
	},
	{
		name: "ControlEvent",
		columns: []msiCatalogColumn{
			{name: "Dialog_", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "Dialog", keyColumn: msiCatInt16(1)},
			{name: "Control_", position: 2, colType: msiColIdentifier, width: 50, key: true, category: "Identifier"},
			{name: "Event", position: 3, colType: msiColFormatted, width: 50, key: true, category: "Formatted"},
			{name: "Argument", position: 4, colType: msiColFormatted, width: 255, key: true, category: "Formatted"},
			{name: "Condition", position: 5, colType: msiColCondition, width: 255, key: true, nullable: true, category: "Condition"},
			{name: "Ordering", position: 6, colType: msiColInteger, width: 2, nullable: true, category: "Integer", minValue: msiCatInt32(0)},
		},
	},
	{
		name: "ControlCondition",
		columns: []msiCatalogColumn{
			{name: "Dialog_", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "Dialog", keyColumn: msiCatInt16(1)},
			{name: "Control_", position: 2, colType: msiColIdentifier, width: 50, key: true, category: "Identifier"},
			{name: "Action", position: 3, colType: msiColText, width: 50, key: true, category: "Text", set: "Default;Disable;Enable;Hide;Show", description: "Default/Disable/Enable/Hide/Show"},
			{name: "Condition", position: 4, colType: msiColCondition, width: 255, key: true, category: "Condition"},
		},
	},
	{
		name: "EventMapping",
		columns: []msiCatalogColumn{
			{name: "Dialog_", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "Dialog", keyColumn: msiCatInt16(1)},
			{name: "Control_", position: 2, colType: msiColIdentifier, width: 50, key: true, category: "Identifier"},
			{name: "Event", position: 3, colType: msiColIdentifier, width: 50, key: true, category: "Identifier", description: "Subscribed event (e.g. SetProgress)"},
			{name: "Attribute", position: 4, colType: msiColIdentifier, width: 50, category: "Identifier", description: "Control attribute updated by the event"},
		},
	},
	{
		name: "TextStyle",
		columns: []msiCatalogColumn{
			{name: "TextStyle", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier"},
			{name: "FaceName", position: 2, colType: msiColText, width: 32, category: "Text"},
			{name: "Size", position: 3, colType: msiColInteger, width: 2, category: "Integer", minValue: msiCatInt32(0)},
			{name: "Color", position: 4, colType: msiColDoubleInteger, width: 4, nullable: true, category: "DoubleInteger", minValue: msiCatInt32(0), description: "RGB color"},
			{name: "StyleBits", position: 5, colType: msiColInteger, width: 2, nullable: true, category: "Integer", description: "1=bold,2=italic,4=underline,8=strike"},
		},
	},
	{
		name: "UIText",
		columns: []msiCatalogColumn{
			{name: "Key", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier"},
			{name: "Text", position: 2, colType: msiColText, width: 255, nullable: true, localizable: true, category: "Text"},
		},
	},
	{
		name: "RadioButton",
		columns: []msiCatalogColumn{
			{name: "Property", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier"},
			{name: "Order", position: 2, colType: msiColInteger, width: 2, key: true, category: "Integer", minValue: msiCatInt32(1)},
			{name: "Value", position: 3, colType: msiColFormatted, width: 64, category: "Formatted"},
			{name: "X", position: 4, colType: msiColInteger, width: 2, category: "Integer"},
			{name: "Y", position: 5, colType: msiColInteger, width: 2, category: "Integer"},
			{name: "Width", position: 6, colType: msiColInteger, width: 2, category: "Integer"},
			{name: "Height", position: 7, colType: msiColInteger, width: 2, category: "Integer"},
			{name: "Text", position: 8, colType: msiColText, width: 0, nullable: true, localizable: true, category: "Text"},
			{name: "Help", position: 9, colType: msiColText, width: 50, nullable: true, localizable: true, category: "Text"},
		},
	},
	{
		name: "ListBox",
		columns: []msiCatalogColumn{
			{name: "Property", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier"},
			{name: "Order", position: 2, colType: msiColInteger, width: 2, key: true, category: "Integer", minValue: msiCatInt32(1)},
			{name: "Value", position: 3, colType: msiColFormatted, width: 64, key: true, category: "Formatted"},
			{name: "Text", position: 4, colType: msiColText, width: 64, nullable: true, localizable: true, category: "Text"},
		},
	},
	{
		name: "ComboBox",
		columns: []msiCatalogColumn{
			{name: "Property", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier"},
			{name: "Order", position: 2, colType: msiColInteger, width: 2, key: true, category: "Integer", minValue: msiCatInt32(1)},
			{name: "Value", position: 3, colType: msiColFormatted, width: 64, key: true, category: "Formatted"},
			{name: "Text", position: 4, colType: msiColFormatted, width: 64, nullable: true, localizable: true, category: "Formatted"},
		},
	},
	{
		name: "ListView",
		columns: []msiCatalogColumn{
			{name: "Property", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier"},
			{name: "Order", position: 2, colType: msiColInteger, width: 2, key: true, category: "Integer", minValue: msiCatInt32(1)},
			{name: "Value", position: 3, colType: msiColIdentifier, width: 64, key: true, category: "Identifier"},
			{name: "Text", position: 4, colType: msiColText, width: 64, nullable: true, localizable: true, category: "Text"},
			{name: "Binary_", position: 5, colType: msiColIdentifier, width: 72, nullable: true, category: "Identifier", keyTable: "Binary", keyColumn: msiCatInt16(1)},
		},
	},
	{
		name: "CheckBox",
		columns: []msiCatalogColumn{
			{name: "Property", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier"},
			{name: "Value", position: 2, colType: msiColFormatted, width: 64, nullable: true, category: "Formatted"},
		},
	},
	{
		name: "Billboard",
		columns: []msiCatalogColumn{
			{name: "Billboard", position: 1, colType: msiColIdentifier, width: 50, key: true, category: "Identifier"},
			{name: "Feature_", position: 2, colType: msiColIdentifier, width: 38, category: "Identifier", keyTable: "Feature", keyColumn: msiCatInt16(1)},
			{name: "Action", position: 3, colType: msiColIdentifier, width: 50, nullable: true, category: "Identifier"},
			{name: "Ordering", position: 4, colType: msiColInteger, width: 2, nullable: true, category: "Integer", minValue: msiCatInt32(0)},
		},
	},
	{
		name: "BBControl",
		columns: []msiCatalogColumn{
			{name: "Billboard_", position: 1, colType: msiColIdentifier, width: 50, key: true, category: "Identifier", keyTable: "Billboard", keyColumn: msiCatInt16(1)},
			{name: "BBControl", position: 2, colType: msiColIdentifier, width: 50, key: true, category: "Identifier"},
			{name: "Type", position: 3, colType: msiColIdentifier, width: 20, category: "Identifier"},
			{name: "X", position: 4, colType: msiColInteger, width: 2, category: "Integer"},
			{name: "Y", position: 5, colType: msiColInteger, width: 2, category: "Integer"},
			{name: "Width", position: 6, colType: msiColInteger, width: 2, category: "Integer"},
			{name: "Height", position: 7, colType: msiColInteger, width: 2, category: "Integer"},
			{name: "Attributes", position: 8, colType: msiColDoubleInteger, width: 4, nullable: true, category: "DoubleInteger"},
			{name: "Text", position: 9, colType: msiColText, width: 0, nullable: true, localizable: true, category: "Text"},
		},
	},
	// --- P10 patch tables (schemas per MS Learn; see memory msp-format-research) ---
	{
		// Patch: authored into the target product database by the patch's
		// metadata transform; describes each patched file's payload.
		name: "Patch",
		columns: []msiCatalogColumn{
			{name: "File_", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "File", keyColumn: msiCatInt16(1), description: "Foreign key to the File table."},
			{name: "Sequence", position: 2, colType: msiColInteger, width: 2, key: true, minValue: msiCatInt32(0), maxValue: msiCatInt32(32767), category: "Integer", description: "Primary key; must match the order of the file in the cabinet."},
			{name: "PatchSize", position: 3, colType: msiColDoubleInteger, width: 4, minValue: msiCatInt32(0), category: "DoubleInteger", description: "Size of the patch in bytes."},
			{name: "Attributes", position: 4, colType: msiColInteger, width: 2, minValue: msiCatInt32(0), category: "Integer", description: "Integer containing bit flags representing patch attributes (0x1 = non-vital)."},
			{name: "Header", position: 5, colType: msiColBinary, width: 0, nullable: true, category: "Binary", description: "The patch header, used for patch validation."},
			{name: "StreamRef_", position: 6, colType: msiColIdentifier, width: 72, nullable: true, category: "Identifier", description: "Foreign key to the MsiPatchHeaders stream that holds the patch header."},
		},
	},
	{
		// PatchPackage: REQUIRED in the patched DB (else error 2768);
		// associates a patch GUID with the disk that delivers its files.
		name: "PatchPackage",
		columns: []msiCatalogColumn{
			{name: "PatchId", position: 1, colType: msiColGUID, width: 38, key: true, category: "Guid", description: "A unique identifier for the patch (the patch code GUID)."},
			{name: "Media_", position: 2, colType: msiColInteger, width: 2, minValue: msiCatInt32(0), maxValue: msiCatInt32(32767), category: "Integer", keyTable: "Media", keyColumn: msiCatInt16(1), description: "Foreign key to the Media table (the DiskId delivering the patch files)."},
		},
	},
	{
		// MsiPatchHeaders: optional indirection for large patch headers; the
		// Header binary lives here when Patch.StreamRef_ points at it.
		name: "MsiPatchHeaders",
		columns: []msiCatalogColumn{
			{name: "StreamRef", position: 1, colType: msiColIdentifier, width: 38, key: true, category: "Identifier", description: "Primary key referenced by Patch.StreamRef_."},
			{name: "Header", position: 2, colType: msiColBinary, width: 0, category: "Binary", description: "Binary stream containing the patch header used for validation."},
		},
	},
	{
		// MsiPatchMetadata: lives in the .msp's OWN database; carries the patch
		// metadata used to display/remove the patch.
		name: "MsiPatchMetadata",
		columns: []msiCatalogColumn{
			{name: "Company", position: 1, colType: msiColIdentifier, width: 72, key: true, nullable: true, category: "Identifier", description: "The company for non-standard properties; null for standard properties."},
			{name: "Property", position: 2, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "The metadata property name (e.g. Classification, DisplayName, AllowRemoval)."},
			{name: "Value", position: 3, colType: msiColText, width: 0, nullable: true, category: "Text", description: "The value of the metadata property."},
		},
	},
	{
		// MsiPatchSequence: lives in the .msp's OWN database; defines the patch
		// family + sequence used for ordering and supersedence.
		name: "MsiPatchSequence",
		columns: []msiCatalogColumn{
			{name: "PatchFamily", position: 1, colType: msiColIdentifier, width: 32, key: true, category: "Identifier", description: "The family to which this patch belongs."},
			{name: "ProductCode", position: 2, colType: msiColGUID, width: 38, key: true, nullable: true, category: "Guid", description: "The product the family applies to; null means all targets."},
			{name: "Sequence", position: 3, colType: msiColVersion, width: 32, category: "Version", description: "The sequence (version) of this patch within the family."},
			{name: "Attributes", position: 4, colType: msiColInteger, width: 2, nullable: true, minValue: msiCatInt32(0), category: "Integer", description: "Bit flags; 0x1 = supersede earlier patches in the family."},
		},
	},
	// --- P11 COM / advertising tables (never emitted by go-msix; cataloged so
	// the generic ICE03 category+FK validator covers them, and the ICE coverage
	// audit can report real validation rather than absence). Schemas per MS Learn. ---
	{
		name: "Class",
		columns: []msiCatalogColumn{
			{name: "CLSID", position: 1, colType: msiColGUID, width: 38, key: true, category: "Guid", description: "The CLSID of a COM server."},
			{name: "Context", position: 2, colType: msiColIdentifier, width: 32, key: true, category: "Identifier", description: "The server context, e.g. LocalServer32."},
			{name: "Component_", position: 3, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1), description: "Foreign key into the Component table."},
			{name: "ProgId_Default", position: 4, colType: msiColText, width: 255, nullable: true, category: "Text", description: "The default ProgId."},
			{name: "Description", position: 5, colType: msiColText, width: 255, nullable: true, localizable: true, category: "Text", description: "Localized class description."},
			{name: "AppId_", position: 6, colType: msiColGUID, width: 38, nullable: true, category: "Guid", keyTable: "AppId", keyColumn: msiCatInt16(1), description: "Foreign key into the AppId table."},
			{name: "FileTypeMask", position: 7, colType: msiColText, width: 255, nullable: true, category: "Text", description: "Pattern + mask for file type matching."},
			{name: "Icon_", position: 8, colType: msiColIdentifier, width: 72, nullable: true, category: "Identifier", keyTable: "Icon", keyColumn: msiCatInt16(1), description: "Foreign key into the Icon table."},
			{name: "IconIndex", position: 9, colType: msiColInteger, width: 2, nullable: true, category: "Integer", description: "Icon index."},
			{name: "DefInprocHandler", position: 10, colType: msiColText, width: 32, nullable: true, category: "Text", description: "The default inproc handler."},
			{name: "Argument", position: 11, colType: msiColFormatted, width: 255, nullable: true, category: "Formatted", description: "Optional command-line argument."},
			{name: "Feature_", position: 12, colType: msiColIdentifier, width: 38, category: "Identifier", keyTable: "Feature", keyColumn: msiCatInt16(1), description: "Foreign key into the Feature table."},
			{name: "Attributes", position: 13, colType: msiColInteger, width: 2, nullable: true, category: "Integer", description: "Class attribute bit flags."},
		},
	},
	{
		name: "ProgId",
		columns: []msiCatalogColumn{
			{name: "ProgId", position: 1, colType: msiColText, width: 255, key: true, category: "Text", description: "The Program Identifier."},
			{name: "ProgId_Parent", position: 2, colType: msiColText, width: 255, nullable: true, category: "Text", keyTable: "ProgId", keyColumn: msiCatInt16(1), description: "The parent ProgId of a version-independent ProgId."},
			{name: "Class_", position: 3, colType: msiColGUID, width: 38, nullable: true, category: "Guid", keyTable: "Class", keyColumn: msiCatInt16(1), description: "Foreign key into the Class table."},
			{name: "Description", position: 4, colType: msiColText, width: 255, nullable: true, localizable: true, category: "Text", description: "Localized description."},
			{name: "Icon_", position: 5, colType: msiColIdentifier, width: 72, nullable: true, category: "Identifier", keyTable: "Icon", keyColumn: msiCatInt16(1), description: "Foreign key into the Icon table."},
			{name: "IconIndex", position: 6, colType: msiColInteger, width: 2, nullable: true, category: "Integer", description: "Icon index."},
		},
	},
	{
		name: "Extension",
		columns: []msiCatalogColumn{
			{name: "Extension", position: 1, colType: msiColText, width: 255, key: true, category: "Text", description: "The file extension (without the dot)."},
			{name: "Component_", position: 2, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1), description: "Foreign key into the Component table."},
			{name: "ProgId_", position: 3, colType: msiColText, width: 255, nullable: true, category: "Text", keyTable: "ProgId", keyColumn: msiCatInt16(1), description: "Foreign key into the ProgId table."},
			{name: "MIME_", position: 4, colType: msiColText, width: 64, nullable: true, category: "Text", keyTable: "MIME", keyColumn: msiCatInt16(1), description: "Foreign key into the MIME table."},
			{name: "Feature_", position: 5, colType: msiColIdentifier, width: 38, category: "Identifier", keyTable: "Feature", keyColumn: msiCatInt16(1), description: "Foreign key into the Feature table."},
		},
	},
	{
		name: "Verb",
		columns: []msiCatalogColumn{
			{name: "Extension_", position: 1, colType: msiColText, width: 255, key: true, category: "Text", keyTable: "Extension", keyColumn: msiCatInt16(1), description: "Foreign key into the Extension table."},
			{name: "Verb", position: 2, colType: msiColText, width: 32, key: true, category: "Text", description: "The verb for the command."},
			{name: "Sequence", position: 3, colType: msiColInteger, width: 2, nullable: true, category: "Integer", description: "Order within the context menu."},
			{name: "Command", position: 4, colType: msiColFormatted, width: 255, nullable: true, localizable: true, category: "Formatted", description: "The localized verb text."},
			{name: "Argument", position: 5, colType: msiColFormatted, width: 255, nullable: true, category: "Formatted", description: "The command-line argument."},
		},
	},
	{
		name: "MIME",
		columns: []msiCatalogColumn{
			{name: "ContentType", position: 1, colType: msiColText, width: 64, key: true, category: "Text", description: "The MIME content type."},
			{name: "Extension_", position: 2, colType: msiColText, width: 255, category: "Text", keyTable: "Extension", keyColumn: msiCatInt16(1), description: "Foreign key into the Extension table."},
			{name: "CLSID", position: 3, colType: msiColGUID, width: 38, nullable: true, category: "Guid", keyTable: "Class", keyColumn: msiCatInt16(1), description: "Optional CLSID of a COM server."},
		},
	},
	{
		name: "TypeLib",
		columns: []msiCatalogColumn{
			{name: "LibID", position: 1, colType: msiColGUID, width: 38, key: true, category: "Guid", description: "The GUID of the type library."},
			{name: "Language", position: 2, colType: msiColInteger, width: 2, key: true, minValue: msiCatInt32(0), maxValue: msiCatInt32(32767), category: "Integer", description: "The language of the type library."},
			{name: "Component_", position: 3, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1), description: "Foreign key into the Component table."},
			{name: "Version", position: 4, colType: msiColDoubleInteger, width: 4, nullable: true, minValue: msiCatInt32(0), category: "DoubleInteger", description: "The version of the type library."},
			{name: "Description", position: 5, colType: msiColText, width: 128, nullable: true, localizable: true, category: "Text", description: "Localized description."},
			{name: "Directory_", position: 6, colType: msiColIdentifier, width: 72, nullable: true, category: "Identifier", keyTable: "Directory", keyColumn: msiCatInt16(1), description: "Foreign key into the Directory table (help dir)."},
			{name: "Feature_", position: 7, colType: msiColIdentifier, width: 38, category: "Identifier", keyTable: "Feature", keyColumn: msiCatInt16(1), description: "Foreign key into the Feature table."},
			{name: "Cost", position: 8, colType: msiColDoubleInteger, width: 4, nullable: true, minValue: msiCatInt32(0), category: "DoubleInteger", description: "The cost in bytes of registering the library."},
		},
	},
	{
		name: "AppId",
		columns: []msiCatalogColumn{
			{name: "AppId", position: 1, colType: msiColGUID, width: 38, key: true, category: "Guid", description: "The AppId GUID."},
			{name: "RemoteServerName", position: 2, colType: msiColFormatted, width: 255, nullable: true, category: "Formatted", description: "The remote server name."},
			{name: "LocalService", position: 3, colType: msiColText, width: 255, nullable: true, category: "Text", description: "The local service name."},
			{name: "ServiceParameters", position: 4, colType: msiColText, width: 255, nullable: true, category: "Text", description: "Service parameters."},
			{name: "DllSurrogate", position: 5, colType: msiColText, width: 255, nullable: true, category: "Text", description: "The DLL surrogate."},
			{name: "ActivateAtStorage", position: 6, colType: msiColInteger, width: 2, nullable: true, category: "Integer", description: "Activate-at-storage flag."},
			{name: "RunAsInteractiveUser", position: 7, colType: msiColInteger, width: 2, nullable: true, category: "Integer", description: "Run-as-interactive-user flag."},
		},
	},
	{
		name: "PublishComponent",
		columns: []msiCatalogColumn{
			{name: "ComponentId", position: 1, colType: msiColGUID, width: 38, key: true, category: "Guid", description: "A GUID that represents the qualified component."},
			{name: "Qualifier", position: 2, colType: msiColText, width: 255, key: true, category: "Text", description: "A string that qualifies the component."},
			{name: "Component_", position: 3, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1), description: "Foreign key into the Component table."},
			{name: "AppData", position: 4, colType: msiColText, width: 255, nullable: true, localizable: true, category: "Text", description: "Application-specific data."},
			{name: "Feature_", position: 5, colType: msiColIdentifier, width: 38, category: "Identifier", keyTable: "Feature", keyColumn: msiCatInt16(1), description: "Foreign key into the Feature table."},
		},
	},
	// --- P11 assembly / font / ODBC tables (never emitted; cataloged for ICE03). ---
	{
		name: "MsiAssembly",
		columns: []msiCatalogColumn{
			{name: "Component_", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1), description: "Foreign key into the Component table."},
			{name: "Feature_", position: 2, colType: msiColIdentifier, width: 38, category: "Identifier", keyTable: "Feature", keyColumn: msiCatInt16(1), description: "Foreign key into the Feature table."},
			{name: "File_Manifest", position: 3, colType: msiColIdentifier, width: 72, nullable: true, category: "Identifier", keyTable: "File", keyColumn: msiCatInt16(1), description: "The assembly manifest file (null for .NET assemblies)."},
			{name: "File_Application", position: 4, colType: msiColIdentifier, width: 72, nullable: true, category: "Identifier", keyTable: "File", keyColumn: msiCatInt16(1), description: "The application file for a private assembly (null for global)."},
			{name: "Attributes", position: 5, colType: msiColInteger, width: 2, nullable: true, category: "Integer", description: "1 = Win32 assembly; 0/null = .NET assembly."},
		},
	},
	{
		name: "MsiAssemblyName",
		columns: []msiCatalogColumn{
			{name: "Component_", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1), description: "Foreign key into the Component table."},
			{name: "Name", position: 2, colType: msiColText, width: 255, key: true, category: "Text", description: "The name part of the strong assembly name."},
			{name: "Value", position: 3, colType: msiColText, width: 255, category: "Text", description: "The value of the assembly name part."},
		},
	},
	{
		name: "Font",
		columns: []msiCatalogColumn{
			{name: "File_", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "File", keyColumn: msiCatInt16(1), description: "The font file (foreign key into File)."},
			{name: "FontTitle", position: 2, colType: msiColText, width: 128, nullable: true, category: "Text", description: "The font title from the font file."},
		},
	},
	{
		name: "ODBCDataSource",
		columns: []msiCatalogColumn{
			{name: "DataSource", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Primary key of the data source."},
			{name: "Component_", position: 2, colType: msiColIdentifier, width: 72, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1), description: "Foreign key into the Component table."},
			{name: "Description", position: 3, colType: msiColText, width: 255, category: "Text", description: "The data source name shown to the user."},
			{name: "DriverDescription", position: 4, colType: msiColText, width: 255, category: "Text", description: "The name of the ODBC driver."},
			{name: "Registration", position: 5, colType: msiColInteger, width: 2, minValue: msiCatInt32(0), maxValue: msiCatInt32(1), category: "Integer", description: "0 = per-machine, 1 = per-user."},
		},
	},
	{
		name: "ODBCDriver",
		columns: []msiCatalogColumn{
			{name: "Driver", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Primary key of the driver."},
			{name: "Component_", position: 2, colType: msiColIdentifier, width: 72, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1), description: "Foreign key into the Component table."},
			{name: "Description", position: 3, colType: msiColText, width: 255, category: "Text", description: "The driver name shown to the user."},
			{name: "File_", position: 4, colType: msiColIdentifier, width: 72, category: "Identifier", keyTable: "File", keyColumn: msiCatInt16(1), description: "The driver DLL (foreign key into File)."},
			{name: "File_Setup", position: 5, colType: msiColIdentifier, width: 72, nullable: true, category: "Identifier", keyTable: "File", keyColumn: msiCatInt16(1), description: "The setup DLL (foreign key into File)."},
		},
	},
	{
		name: "ODBCTranslator",
		columns: []msiCatalogColumn{
			{name: "Translator", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Primary key of the translator."},
			{name: "Component_", position: 2, colType: msiColIdentifier, width: 72, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1), description: "Foreign key into the Component table."},
			{name: "Description", position: 3, colType: msiColText, width: 255, category: "Text", description: "The translator name shown to the user."},
			{name: "File_", position: 4, colType: msiColIdentifier, width: 72, category: "Identifier", keyTable: "File", keyColumn: msiCatInt16(1), description: "The translator DLL (foreign key into File)."},
			{name: "File_Setup", position: 5, colType: msiColIdentifier, width: 72, nullable: true, category: "Identifier", keyTable: "File", keyColumn: msiCatInt16(1), description: "The setup DLL (foreign key into File)."},
		},
	},
	{
		name: "ODBCAttribute",
		columns: []msiCatalogColumn{
			{name: "Driver_", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "ODBCDriver", keyColumn: msiCatInt16(1), description: "Foreign key into the ODBCDriver table."},
			{name: "Attribute", position: 2, colType: msiColText, width: 40, key: true, category: "Text", description: "The name of the driver attribute."},
			{name: "Value", position: 3, colType: msiColText, width: 255, nullable: true, category: "Text", description: "The value of the driver attribute."},
		},
	},
	{
		name: "ODBCSourceAttribute",
		columns: []msiCatalogColumn{
			{name: "DataSource_", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "ODBCDataSource", keyColumn: msiCatInt16(1), description: "Foreign key into the ODBCDataSource table."},
			{name: "Attribute", position: 2, colType: msiColText, width: 32, key: true, category: "Text", description: "The name of the data source attribute."},
			{name: "Value", position: 3, colType: msiColText, width: 255, nullable: true, category: "Text", description: "The value of the data source attribute."},
		},
	},
	// --- P11 file-ops / registration / security tables (never emitted; ICE03). ---
	{
		name: "DuplicateFile",
		columns: []msiCatalogColumn{
			{name: "FileKey", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Primary key."},
			{name: "Component_", position: 2, colType: msiColIdentifier, width: 72, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1), description: "Foreign key into the Component table."},
			{name: "File_", position: 3, colType: msiColIdentifier, width: 72, category: "Identifier", keyTable: "File", keyColumn: msiCatInt16(1), description: "Foreign key into the File table (the file to duplicate)."},
			{name: "DestName", position: 4, colType: msiColFilename, width: 255, nullable: true, localizable: true, category: "Filename", description: "Optional new file name."},
			{name: "DestFolder", position: 5, colType: msiColIdentifier, width: 72, nullable: true, category: "Identifier", keyTable: "Directory", keyColumn: msiCatInt16(1), description: "Optional destination directory property."},
		},
	},
	{
		name: "MoveFile",
		columns: []msiCatalogColumn{
			{name: "FileKey", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Primary key."},
			{name: "Component_", position: 2, colType: msiColIdentifier, width: 72, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1), description: "Foreign key into the Component table."},
			{name: "SourceName", position: 3, colType: msiColText, width: 255, nullable: true, category: "Text", description: "Source file name(s) / wildcard."},
			{name: "DestName", position: 4, colType: msiColFilename, width: 255, nullable: true, localizable: true, category: "Filename", description: "Destination name."},
			{name: "SourceFolder", position: 5, colType: msiColIdentifier, width: 72, nullable: true, category: "Identifier", keyTable: "Directory", keyColumn: msiCatInt16(1), description: "Source directory property."},
			{name: "DestFolder", position: 6, colType: msiColIdentifier, width: 72, category: "Identifier", keyTable: "Directory", keyColumn: msiCatInt16(1), description: "Destination directory property."},
			{name: "Options", position: 7, colType: msiColInteger, width: 2, minValue: msiCatInt32(0), maxValue: msiCatInt32(1), category: "Integer", description: "0 = copy, 1 = move."},
		},
	},
	{
		name: "IniFile",
		columns: []msiCatalogColumn{
			{name: "IniFile", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Primary key."},
			{name: "FileName", position: 2, colType: msiColFilename, width: 255, localizable: true, category: "Filename", description: "The .ini file name."},
			{name: "DirProperty", position: 3, colType: msiColIdentifier, width: 72, nullable: true, category: "Identifier", description: "A property naming the directory of the .ini file."},
			{name: "Section", position: 4, colType: msiColFormatted, width: 96, category: "Formatted", description: "The .ini section."},
			{name: "Key", position: 5, colType: msiColFormatted, width: 128, category: "Formatted", description: "The key within the section."},
			{name: "Value", position: 6, colType: msiColFormatted, width: 255, category: "Formatted", description: "The value to write."},
			{name: "Action", position: 7, colType: msiColInteger, width: 2, category: "Integer", description: "0 = add line, 1 = create/replace, 3 = add tag."},
			{name: "Component_", position: 8, colType: msiColIdentifier, width: 72, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1), description: "Foreign key into the Component table."},
		},
	},
	{
		name: "RemoveIniFile",
		columns: []msiCatalogColumn{
			{name: "RemoveIniFile", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Primary key."},
			{name: "FileName", position: 2, colType: msiColFilename, width: 255, localizable: true, category: "Filename", description: "The .ini file name."},
			{name: "DirProperty", position: 3, colType: msiColIdentifier, width: 72, nullable: true, category: "Identifier", description: "A property naming the directory of the .ini file."},
			{name: "Section", position: 4, colType: msiColFormatted, width: 96, category: "Formatted", description: "The .ini section."},
			{name: "Key", position: 5, colType: msiColFormatted, width: 128, category: "Formatted", description: "The key within the section."},
			{name: "Value", position: 6, colType: msiColFormatted, width: 255, nullable: true, category: "Formatted", description: "The value to remove."},
			{name: "Action", position: 7, colType: msiColInteger, width: 2, category: "Integer", description: "2 = remove line, 4 = remove tag."},
			{name: "Component_", position: 8, colType: msiColIdentifier, width: 72, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1), description: "Foreign key into the Component table."},
		},
	},
	{
		name: "IsolatedComponent",
		columns: []msiCatalogColumn{
			{name: "Component_Shared", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1), description: "The shared component to copy."},
			{name: "Component_Application", position: 2, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1), description: "The application component receiving the private copy."},
		},
	},
	{
		name: "BindImage",
		columns: []msiCatalogColumn{
			{name: "File_", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "File", keyColumn: msiCatInt16(1), description: "The executable/DLL to bind (foreign key into File)."},
			{name: "Path", position: 2, colType: msiColPaths, width: 255, nullable: true, category: "Paths", description: "Paths used to find the imported DLLs."},
		},
	},
	{
		name: "SelfReg",
		columns: []msiCatalogColumn{
			{name: "File_", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "File", keyColumn: msiCatInt16(1), description: "The module to self-register (foreign key into File)."},
			{name: "Cost", position: 2, colType: msiColInteger, width: 2, nullable: true, minValue: msiCatInt32(0), category: "Integer", description: "The estimated registration cost."},
		},
	},
	{
		name: "ReserveCost",
		columns: []msiCatalogColumn{
			{name: "ReserveKey", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Primary key."},
			{name: "Component_", position: 2, colType: msiColIdentifier, width: 72, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1), description: "Foreign key into the Component table."},
			{name: "ReserveFolder", position: 3, colType: msiColIdentifier, width: 72, nullable: true, category: "Identifier", keyTable: "Directory", keyColumn: msiCatInt16(1), description: "A property naming the directory to reserve space in."},
			{name: "ReserveLocal", position: 4, colType: msiColDoubleInteger, width: 4, minValue: msiCatInt32(0), category: "DoubleInteger", description: "Bytes to reserve when installed locally."},
			{name: "ReserveSource", position: 5, colType: msiColDoubleInteger, width: 4, minValue: msiCatInt32(0), category: "DoubleInteger", description: "Bytes to reserve when run from source."},
		},
	},
	{
		name: "Complus",
		columns: []msiCatalogColumn{
			{name: "Component_", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1), description: "Foreign key into the Component table."},
			{name: "ExpType", position: 2, colType: msiColInteger, width: 2, nullable: true, minValue: msiCatInt32(0), category: "Integer", description: "The COM+ application export type."},
		},
	},
	{
		name: "LockPermissions",
		columns: []msiCatalogColumn{
			{name: "LockObject", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "The object to secure (key into Table)."},
			{name: "Table", position: 2, colType: msiColIdentifier, width: 32, key: true, category: "Identifier", description: "The table containing LockObject (Directory/File/Registry/CreateFolder/ServiceInstall)."},
			{name: "Domain", position: 3, colType: msiColFormatted, width: 255, key: true, nullable: true, category: "Formatted", description: "The domain of the user/group."},
			{name: "User", position: 4, colType: msiColFormatted, width: 255, key: true, category: "Formatted", description: "The user/group name."},
			{name: "Permission", position: 5, colType: msiColDoubleInteger, width: 4, nullable: true, category: "DoubleInteger", description: "The access-rights bit mask."},
		},
	},
	{
		name: "MsiLockPermissionsEx",
		columns: []msiCatalogColumn{
			{name: "MsiLockPermissionsEx", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Primary key."},
			{name: "LockObject", position: 2, colType: msiColIdentifier, width: 72, category: "Identifier", description: "The object to secure (key into Table)."},
			{name: "Table", position: 3, colType: msiColIdentifier, width: 32, category: "Identifier", description: "The table containing LockObject."},
			{name: "SDDLText", position: 4, colType: msiColFormattedSDDLText, width: 255, category: "FormattedSDDLText", description: "The SDDL string describing the security descriptor."},
			{name: "Condition", position: 5, colType: msiColCondition, width: 255, nullable: true, category: "Condition", description: "An optional condition."},
		},
	},
	{
		name: "MsiDigitalCertificate",
		columns: []msiCatalogColumn{
			{name: "DigitalCertificate", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Primary key."},
			{name: "CertData", position: 2, colType: msiColBinary, width: 0, category: "Binary", description: "The binary certificate data."},
		},
	},
	{
		name: "MsiDigitalSignature",
		columns: []msiCatalogColumn{
			{name: "Table", position: 1, colType: msiColIdentifier, width: 32, key: true, category: "Identifier", description: "The table of the signed object (only \"Media\")."},
			{name: "SignObject", position: 2, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "The signed object's key."},
			{name: "DigitalCertificate_", position: 3, colType: msiColIdentifier, width: 72, category: "Identifier", keyTable: "MsiDigitalCertificate", keyColumn: msiCatInt16(1), description: "Foreign key into MsiDigitalCertificate."},
			{name: "Hash", position: 4, colType: msiColBinary, width: 0, nullable: true, category: "Binary", description: "The optional hash of the signed object."},
		},
	},
	{
		name: "MsiEmbeddedChainer",
		columns: []msiCatalogColumn{
			{name: "MsiEmbeddedChainer", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Primary key."},
			{name: "Condition", position: 2, colType: msiColCondition, width: 255, nullable: true, category: "Condition", description: "A condition gating the chainer."},
			{name: "CommandLine", position: 3, colType: msiColFormatted, width: 255, nullable: true, category: "Formatted", description: "The chainer command line."},
			{name: "Source", position: 4, colType: msiColCustomSource, width: 72, category: "CustomSource", description: "The chainer source (Binary/File/Property/Directory key)."},
			{name: "Type", position: 5, colType: msiColDoubleInteger, width: 4, category: "DoubleInteger", description: "The source type bits (mirrors CustomAction.Type)."},
		},
	},
	{
		name: "MsiEmbeddedUI",
		columns: []msiCatalogColumn{
			{name: "MsiEmbeddedUI", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "Primary key."},
			{name: "FileName", position: 2, colType: msiColFilename, width: 255, category: "Filename", description: "The embedded-UI resource file name."},
			{name: "Attributes", position: 3, colType: msiColInteger, width: 2, category: "Integer", description: "Bit flags (1 = the embedded UI DLL, 2 = handles messages)."},
			{name: "MessageFilter", position: 4, colType: msiColDoubleInteger, width: 4, nullable: true, category: "DoubleInteger", description: "The message-type filter bit mask."},
			{name: "Data", position: 5, colType: msiColBinary, width: 0, nullable: true, category: "Binary", description: "The binary resource payload."},
		},
	},
	// --- P11 merge-module tables (appear only in .msm files, which go-msix does
	// not produce; cataloged so ICE03 + the mergemod-scope ICEs can validate
	// them via synthetic databases). Schemas per MS Learn. ---
	{
		name: "ModuleSignature",
		columns: []msiCatalogColumn{
			{name: "ModuleID", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "The merge module identifier (name.GUID)."},
			{name: "Language", position: 2, colType: msiColInteger, width: 2, key: true, category: "Integer", description: "The default language of the module."},
			{name: "Version", position: 3, colType: msiColVersion, width: 32, category: "Version", description: "The version of the module."},
		},
	},
	{
		name: "ModuleComponents",
		columns: []msiCatalogColumn{
			{name: "Component", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "Component", keyColumn: msiCatInt16(1), description: "Foreign key into the Component table."},
			{name: "ModuleID", position: 2, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "ModuleSignature", keyColumn: msiCatInt16(1), description: "Foreign key into the ModuleSignature table."},
			{name: "Language", position: 3, colType: msiColInteger, width: 2, key: true, category: "Integer", description: "The language of the module containing the component."},
		},
	},
	{
		name: "ModuleDependency",
		columns: []msiCatalogColumn{
			{name: "ModuleID", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "ModuleSignature", keyColumn: msiCatInt16(1), description: "Foreign key into the ModuleSignature table."},
			{name: "ModuleLanguage", position: 2, colType: msiColInteger, width: 2, key: true, category: "Integer", description: "The language of the dependent module."},
			{name: "RequiredID", position: 3, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "The required module's identifier."},
			{name: "RequiredLanguage", position: 4, colType: msiColInteger, width: 2, key: true, category: "Integer", description: "The required module's language."},
			{name: "RequiredVersion", position: 5, colType: msiColVersion, width: 32, nullable: true, category: "Version", description: "The required module's version."},
		},
	},
	{
		name: "ModuleExclusion",
		columns: []msiCatalogColumn{
			{name: "ModuleID", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", keyTable: "ModuleSignature", keyColumn: msiCatInt16(1), description: "Foreign key into the ModuleSignature table."},
			{name: "ModuleLanguage", position: 2, colType: msiColInteger, width: 2, key: true, category: "Integer", description: "The language of the excluding module."},
			{name: "ExcludedID", position: 3, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "The excluded module's identifier."},
			{name: "ExcludedLanguage", position: 4, colType: msiColInteger, width: 2, key: true, category: "Integer", description: "The excluded module's language (signed: negate to exclude all but)."},
			{name: "ExcludedMinVersion", position: 5, colType: msiColVersion, width: 32, nullable: true, category: "Version", description: "The minimum excluded version."},
			{name: "ExcludedMaxVersion", position: 6, colType: msiColVersion, width: 32, nullable: true, category: "Version", description: "The maximum excluded version."},
		},
	},
	{
		name: "ModuleConfiguration",
		columns: []msiCatalogColumn{
			{name: "Name", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "The configurable item name."},
			{name: "Format", position: 2, colType: msiColInteger, width: 2, category: "Integer", description: "The data format (0=Text,1=Key,2=Integer,3=Bitfield)."},
			{name: "Type", position: 3, colType: msiColText, width: 32, nullable: true, category: "Text", description: "The display type for the authoring tool."},
			{name: "ContextData", position: 4, colType: msiColText, width: 72, nullable: true, category: "Text", description: "Semantic context for the authoring tool."},
			{name: "DefaultValue", position: 5, colType: msiColFormatted, width: 255, nullable: true, category: "Formatted", description: "The default value of the item."},
			{name: "Attributes", position: 6, colType: msiColInteger, width: 2, nullable: true, category: "Integer", description: "Configuration attribute bit flags."},
			{name: "DisplayName", position: 7, colType: msiColText, width: 255, nullable: true, category: "Text", description: "The display name shown to the user."},
			{name: "Description", position: 8, colType: msiColText, width: 255, nullable: true, category: "Text", description: "The description shown to the user."},
			{name: "HelpLocation", position: 9, colType: msiColText, width: 255, nullable: true, category: "Text", description: "The help file location."},
			{name: "HelpKeyword", position: 10, colType: msiColText, width: 255, nullable: true, category: "Text", description: "The help keyword."},
		},
	},
	{
		name: "ModuleSubstitution",
		columns: []msiCatalogColumn{
			{name: "Table", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "The table holding the row to configure."},
			{name: "Row", position: 2, colType: msiColFormatted, width: 255, key: true, category: "Formatted", description: "The primary keys of the row to configure."},
			{name: "Column", position: 3, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "The column to configure."},
			{name: "Value", position: 4, colType: msiColFormatted, width: 255, nullable: true, category: "Formatted", description: "The replacement template referencing ModuleConfiguration items."},
		},
	},
	{
		name: "ModuleIgnoreTable",
		columns: []msiCatalogColumn{
			{name: "Table", position: 1, colType: msiColIdentifier, width: 72, key: true, category: "Identifier", description: "A table the merge tool should not merge."},
		},
	},
	moduleSeqCatalogDef("ModuleInstallExecuteSequence"),
	moduleSeqCatalogDef("ModuleInstallUISequence"),
	moduleSeqCatalogDef("ModuleAdminExecuteSequence"),
	moduleSeqCatalogDef("ModuleAdminUISequence"),
}

// allMSICatalogTables returns the canonical table definitions in a fixed,
// deterministic order (standard tables first, _Validation last). The returned
// slice is shared; callers must not mutate it.
func allMSICatalogTables() []msiCatalogTableDef {
	return msiTableCatalog
}

// msiCatalogTable looks up a canonical table definition by name.
func msiCatalogTable(name string) (msiCatalogTableDef, bool) {
	for _, def := range msiTableCatalog {
		if def.name == name {
			return def, true
		}
	}
	return msiCatalogTableDef{}, false
}
