// Package serviceidentity reserves identities inside the provider's 65536-ID
// user-namespace mapping. These identities belong only to sealed's services.
package serviceidentity

const (
	CoordinatorBase  = 50000
	CoordinatorCount = 16
	WorkerBase       = 51000
	WorkerCount      = 32
)

func Valid(uid int) bool {
	return (uid >= CoordinatorBase && uid < CoordinatorBase+CoordinatorCount) ||
		(uid >= WorkerBase && uid < WorkerBase+WorkerCount)
}
