package msi

import (
	"reflect"
	"unsafe"
)

// msi_clone.go — deep clone of a built *msiPackage, used to derive an embedded
// language transform's target from the base (WithLanguageTransform). A reflective
// deep copy is used deliberately: it clones every pointer/slice/map/struct field
// (including unexported ones, via unsafe addressable aliases) so that a future
// field added to msiPackage is cloned automatically rather than silently shared
// and leaked across the base→target diff. Funcs, channels and interface values
// are shared (shallow) because they cannot be meaningfully duplicated; the clone
// clears the ones that matter (signer, languageTransforms) right after copying.

// cloneForTransform returns an independent deep copy of p suitable as a
// transform target: configure(clone) may mutate it freely without touching the
// base. The clone carries no signer, no nested language transforms, and no
// accumulated builder errors.
func (p *msiPackage) cloneForTransform() *msiPackage {
	seen := map[unsafe.Pointer]reflect.Value{}
	cp := deepCopyValue(reflect.ValueOf(p), seen).Interface().(*msiPackage)
	cp.languageTransforms = nil
	cp.signer = nil
	cp.errs = nil
	return cp
}

// deepCopyValue recursively deep-copies v. seen guards against pointer cycles
// (the msiPackage model is acyclic, but the guard keeps the copy total).
func deepCopyValue(v reflect.Value, seen map[unsafe.Pointer]reflect.Value) reflect.Value {
	if !v.IsValid() {
		return v
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			return v
		}
		key := unsafe.Pointer(v.Pointer())
		if existing, ok := seen[key]; ok {
			return existing
		}
		out := reflect.New(v.Elem().Type())
		seen[key] = out
		out.Elem().Set(deepCopyValue(v.Elem(), seen))
		return out

	case reflect.Interface:
		// Share the concrete value (interfaces here hold funcs/keys); the
		// caller clears the ones that must not be shared.
		return v

	case reflect.Slice:
		if v.IsNil() {
			return v
		}
		out := reflect.MakeSlice(v.Type(), v.Len(), v.Cap())
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(deepCopyValue(v.Index(i), seen))
		}
		return out

	case reflect.Map:
		if v.IsNil() {
			return v
		}
		out := reflect.MakeMapWithSize(v.Type(), v.Len())
		iter := v.MapRange()
		for iter.Next() {
			out.SetMapIndex(deepCopyValue(iter.Key(), seen), deepCopyValue(iter.Value(), seen))
		}
		return out

	case reflect.Struct:
		src := v
		if !src.CanAddr() {
			tmp := reflect.New(v.Type()).Elem()
			tmp.Set(v)
			src = tmp
		}
		out := reflect.New(v.Type()).Elem()
		for i := 0; i < src.NumField(); i++ {
			fv := src.Field(i)
			of := out.Field(i)
			if !of.CanSet() {
				// Unexported field: alias both sides as settable via unsafe.
				fv = reflect.NewAt(fv.Type(), unsafe.Pointer(fv.UnsafeAddr())).Elem()
				of = reflect.NewAt(of.Type(), unsafe.Pointer(of.UnsafeAddr())).Elem()
			}
			of.Set(deepCopyValue(fv, seen))
		}
		return out

	case reflect.Array:
		out := reflect.New(v.Type()).Elem()
		for i := 0; i < v.Len(); i++ {
			out.Index(i).Set(deepCopyValue(v.Index(i), seen))
		}
		return out

	default:
		// Basic kinds, func, chan, unsafe.Pointer: value copy / shared ref.
		return v
	}
}
