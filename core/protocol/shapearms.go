package protocol

// shapeArms holds the padding profiles the datapath controller rotates between.
var shapeArms = []struct {
	name    string
	records int
	min     int
	max     int
}{
	{"off", 0, 0, 0},
	{"default", shapePadRecords, shapePadMin, shapePadMax},
	{"short", 6, 32, 256},
	{"wide", 2, 400, 2400},
}

func ShapeArmCount() int { return len(shapeArms) }

func ShapeArmName(i int) string {
	if i < 0 || i >= len(shapeArms) {
		return "unknown"
	}
	return shapeArms[i].name
}

func ApplyShapeArm(i int) error {
	if i < 0 || i >= len(shapeArms) {
		i = 0
	}
	a := shapeArms[i]
	return Shape.Set(a.records, a.min, a.max)
}
