package msi

import (
	"fmt"
	"strings"
)

// DefaultDir is MSI syntax: target[:source], with optional short|long pairs
// and the '.' same-directory sentinel. Only its ordinary name parts undergo
// Windows filename validation; punctuation belonging to MSI syntax does not.
func directoryNameParts(value string) (target, source string, hasSource bool, err error) {
	target, source, hasSource = strings.Cut(value, ":")
	if strings.Contains(source, ":") {
		err = fmt.Errorf("invalid DefaultDir %q", value)
	}
	return
}

func shortLongName(value string) (short, long string, explicit bool, err error) {
	short, long, explicit = strings.Cut(value, "|")
	if !explicit {
		long = short
		short = ""
	}
	if err = msiValidateLongName(long); err != nil {
		return
	}
	if explicit {
		if err = msiValidateLongName(short); err != nil {
			return
		}
		if !msiIsValidShortName(short) {
			err = fmt.Errorf("invalid explicit short name %q", short)
		}
	}
	return
}

func (n *msiShortNamer) reserve(value string) error {
	short, long, explicit, err := shortLongName(value)
	if err != nil {
		return err
	}
	if !explicit && msiIsValidShortName(long) {
		short = long
	}
	if short != "" {
		n.used[strings.ToUpper(short)] = struct{}{}
	}
	return nil
}

func (n *msiShortNamer) directoryPart(value string) (string, error) {
	if value == "." {
		return value, nil
	}
	short, long, explicit, err := shortLongName(value)
	if err != nil {
		return "", err
	}
	if !explicit {
		return n.msiFileNameColumn(long)
	}
	if err := n.claim(long, short); err != nil {
		return "", err
	}
	return short + "|" + long, nil
}

func (n *msiShortNamer) claim(long, short string) error {
	if n.longNames == nil {
		n.longNames = map[string]bool{}
		n.issued = map[string]bool{}
	}
	key, alias := strings.ToUpper(long), strings.ToUpper(short)
	if n.longNames[key] || n.issued[alias] {
		return fmt.Errorf("msi shortname: duplicate sibling name or alias %q (%q)", long, short)
	}
	n.longNames[key], n.issued[alias] = true, true
	n.used[alias] = struct{}{}
	return nil
}
