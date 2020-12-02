package lib

import "encoding/xml"

type SSO struct {
	XMLName xml.Name  `xml:"EntityDescriptor"`
	Sig     Signature `xml:"Signature"`
}

type Signature struct {
	XMLName xml.Name `xml:"Signature"`
	KeyInfo KeyInfo  `xml:"KeyInfo"`
}

type KeyInfo struct {
	XMLName  xml.Name `xml:"KeyInfo"`
	X509Data X509Data `xml:"X509Data"`
}

type X509Data struct {
	XMLName xml.Name `xml:"X509Data"`
	Cert    string   `xml:"X509Certificate"`
}
