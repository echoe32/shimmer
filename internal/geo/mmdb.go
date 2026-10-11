package geo

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

// mmdbLookup reads a local MaxMind database. Offline, microseconds per query.
// Either database may be absent; the corresponding fields stay empty.
type mmdbLookup struct {
	city *maxminddb.Reader
	asn  *maxminddb.Reader
}

// cityRecord is the slice of the City database this program needs.
type cityRecord struct {
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
}

// asnRecord is the slice of the ASN database this program needs.
type asnRecord struct {
	Number uint   `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

// NewMMDB opens the database files at the given paths.
// An empty path means "skip that database"; both empty is an error, since the
// caller would get nothing back.
func NewMMDB(cityPath, asnPath string) (Lookup, error) {
	if cityPath == "" && asnPath == "" {
		return nil, errors.New("geo: no MaxMind database given")
	}
	m := &mmdbLookup{}
	if cityPath != "" {
		db, err := maxminddb.Open(cityPath)
		if err != nil {
			return nil, fmt.Errorf("open city database: %w", err)
		}
		m.city = db
	}
	if asnPath != "" {
		db, err := maxminddb.Open(asnPath)
		if err != nil {
			if m.city != nil {
				m.city.Close()
			}
			return nil, fmt.Errorf("open ASN database: %w", err)
		}
		m.asn = db
	}
	return m, nil
}

func (m *mmdbLookup) Lookup(ctx context.Context, addr netip.Addr) (*Info, error) {
	if !addr.IsValid() {
		return nil, errors.New("geo: invalid address")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	addr = addr.Unmap()

	info := &Info{}
	if m.city != nil {
		var rec cityRecord
		if err := m.city.Lookup(addr).Decode(&rec); err != nil {
			return nil, fmt.Errorf("city lookup %s: %w", addr, err)
		}
		info.Country = rec.Country.ISOCode
		if info.Country == "" {
			info.Country = rec.RegisteredCountry.ISOCode
		}
	}
	if m.asn != nil {
		var rec asnRecord
		if err := m.asn.Lookup(addr).Decode(&rec); err != nil {
			return nil, fmt.Errorf("ASN lookup %s: %w", addr, err)
		}
		info.ASN = rec.Number
		info.Org = rec.Org
	}
	return info, nil
}

// Close releases both databases.
func (m *mmdbLookup) Close() error {
	var err error
	if m.city != nil {
		err = errors.Join(err, m.city.Close())
	}
	if m.asn != nil {
		err = errors.Join(err, m.asn.Close())
	}
	return err
}
