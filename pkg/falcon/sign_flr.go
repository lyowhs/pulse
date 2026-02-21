package fndsa

// Some useful constants:
//   bNN    2^NN
//   mNN    2^NN - 1

const b52 = uint64(0x0010000000000000)
const b53 = uint64(0x0020000000000000)
const b62 = uint64(0x4000000000000000)
const b63 = uint64(0x8000000000000000)

const m50 = uint64(0x0003FFFFFFFFFFFF)
const m52 = uint64(0x000FFFFFFFFFFFFF)
const m62 = uint64(0x3FFFFFFFFFFFFFFF)
const m63 = uint64(0x7FFFFFFFFFFFFFFF)
