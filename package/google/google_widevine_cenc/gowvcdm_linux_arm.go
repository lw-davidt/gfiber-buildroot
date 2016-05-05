package gowvcdm

// #cgo CXXFLAGS: -I../../../../core/include -std=c++11
// #cgo CXXFLAGS: -I../../../../platforms/spacecast/include
// #cgo CXXFLAGS: -I../../../../out/Release/obj/gen/protoc_out
// #cgo LDFLAGS: -L../../../../out/Release
// #cgo LDFLAGS: -lwidevine_ce_cdm_static -lwidevine_cdm_core -llicense_protocol
// #cgo LDFLAGS: -lprotobuf -lwidevine_ce_cdm_static -loec_mock -lcrypto -ldevice_files
import "C"
