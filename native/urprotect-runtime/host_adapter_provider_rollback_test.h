#ifndef URP_HOST_ADAPTER_PROVIDER_ROLLBACK_TEST_H
#define URP_HOST_ADAPTER_PROVIDER_ROLLBACK_TEST_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>

#define URP_HOST_ADAPTER_TEST_ROLLBACK_MAX_EVENTS 32U
#define URP_HOST_ADAPTER_TEST_ROLLBACK_MAX_MAPS 32U
#define URP_HOST_ADAPTER_TEST_ROLLBACK_MAX_PROCESS_MAPS 256U
#define URP_HOST_ADAPTER_TEST_ROLLBACK_MAP_LINE_BYTES 1024U

typedef enum urp_host_adapter_test_rollback_event {
    URP_TEST_EVENT_PROVIDER_ACQUIRED = 1,
    URP_TEST_EVENT_CONSUMER_DLMOPEN_SUCCEEDED = 2,
    URP_TEST_EVENT_PROVIDER_BINDING_VERIFIED = 3,
    URP_TEST_EVENT_BINDING_FAILPOINT_REACHED = 4,
    URP_TEST_EVENT_FAILURE_CONSUMER_DLCLOSE_RETURNED = 5,
    URP_TEST_EVENT_FAILURE_CONSUMER_FD_CLOSE_RETURNED = 6,
    URP_TEST_EVENT_PROVIDER_DLCLOSE_RETURNED = 7,
    URP_TEST_EVENT_PROVIDER_FD_CLOSE_RETURNED = 8,
    URP_TEST_EVENT_PROVIDER_RELEASE_RETURNED = 9,
    URP_TEST_EVENT_FIRST_LOAD_REJECTED = 10,
    URP_TEST_EVENT_IMAGE_HANDLE_PUBLISHED = 11,
    URP_TEST_EVENT_IMAGE_RELEASE_STARTED = 12,
    URP_TEST_EVENT_IMAGE_DLCLOSE_RETURNED = 13,
    URP_TEST_EVENT_IMAGE_FD_CLOSE_RETURNED = 14,
    URP_TEST_EVENT_IMAGE_RELEASE_RETURNED = 15,
} urp_host_adapter_test_rollback_event;

typedef struct urp_host_adapter_test_file_identity {
    uint32_t deviceMajor;
    uint32_t deviceMinor;
    uint64_t inode;
} urp_host_adapter_test_file_identity;

typedef struct urp_host_adapter_test_mapping {
    uint64_t start;
    uint64_t end;
    uint64_t offset;
    uint32_t deviceMajor;
    uint32_t deviceMinor;
    uint64_t inode;
    char permissions[5];
} urp_host_adapter_test_mapping;

/* Read-only, bounded observation of the exact backing object used by proc maps. */
static inline int urp_host_adapter_test_identity_from_stat(
    const struct stat *status,
    urp_host_adapter_test_file_identity *identity)
{
    if (status == NULL || identity == NULL || !S_ISREG(status->st_mode) || status->st_ino <= 0) return 0;
    unsigned long long major_value = (unsigned long long)major(status->st_dev);
    unsigned long long minor_value = (unsigned long long)minor(status->st_dev);
    if (major_value > UINT32_MAX || minor_value > UINT32_MAX) return 0;
    identity->deviceMajor = (uint32_t)major_value;
    identity->deviceMinor = (uint32_t)minor_value;
    identity->inode = (uint64_t)status->st_ino;
    return 1;
}

static inline int urp_host_adapter_test_identity_from_fd(
    int descriptor,
    urp_host_adapter_test_file_identity *identity)
{
    struct stat status;
    return fstat(descriptor, &status) == 0
        && urp_host_adapter_test_identity_from_stat(&status, identity);
}

static inline int urp_host_adapter_test_identity_from_path(
    const char *path,
    urp_host_adapter_test_file_identity *identity)
{
    struct stat status;
    return path != NULL && stat(path, &status) == 0
        && urp_host_adapter_test_identity_from_stat(&status, identity);
}

static inline int urp_host_adapter_test_capture_process_mappings(
    urp_host_adapter_test_mapping *mappings,
    size_t capacity,
    uint32_t *count_out)
{
    if (mappings == NULL || count_out == NULL || capacity == 0U) return 0;
    FILE *maps_file = fopen("/proc/self/maps", "r");
    if (maps_file == NULL) return 0;
    size_t count = 0U;
    char line[URP_HOST_ADAPTER_TEST_ROLLBACK_MAP_LINE_BYTES];
    int valid = 1;
    while (fgets(line, sizeof(line), maps_file) != NULL) {
        unsigned long long start = 0U;
        unsigned long long end = 0U;
        unsigned long long offset = 0U;
        unsigned int device_major = 0U;
        unsigned int device_minor = 0U;
        unsigned long long inode = 0U;
        char permissions[5] = {0};
        int fields = sscanf(line, "%llx-%llx %4s %llx %x:%x %llu",
            &start, &end, permissions, &offset, &device_major, &device_minor, &inode);
        if (fields != 7 || start >= end
            || (permissions[0] != 'r' && permissions[0] != '-')
            || (permissions[1] != 'w' && permissions[1] != '-')
            || (permissions[2] != 'x' && permissions[2] != '-')
            || (permissions[3] != 'p' && permissions[3] != 's')
            || count >= capacity) {
            valid = 0;
            break;
        }
        urp_host_adapter_test_mapping *mapping = &mappings[count++];
        mapping->start = (uint64_t)start;
        mapping->end = (uint64_t)end;
        mapping->offset = (uint64_t)offset;
        mapping->deviceMajor = device_major;
        mapping->deviceMinor = device_minor;
        mapping->inode = (uint64_t)inode;
        memcpy(mapping->permissions, permissions, sizeof(mapping->permissions));
    }
    if (ferror(maps_file) != 0) valid = 0;
    if (fclose(maps_file) != 0) valid = 0;
    if (!valid) return 0;
    *count_out = (uint32_t)count;
    return 1;
}

static inline int urp_host_adapter_test_capture_mappings(
    const urp_host_adapter_test_file_identity *identity,
    urp_host_adapter_test_mapping *mappings,
    size_t capacity,
    uint32_t *count_out)
{
    if (identity == NULL || mappings == NULL || count_out == NULL || capacity == 0U) return 0;
    FILE *maps_file = fopen("/proc/self/maps", "r");
    if (maps_file == NULL) return 0;
    size_t count = 0U;
    char line[URP_HOST_ADAPTER_TEST_ROLLBACK_MAP_LINE_BYTES];
    int valid = 1;
    while (fgets(line, sizeof(line), maps_file) != NULL) {
        unsigned long long start = 0U;
        unsigned long long end = 0U;
        unsigned long long offset = 0U;
        unsigned int device_major = 0U;
        unsigned int device_minor = 0U;
        unsigned long long inode = 0U;
        char permissions[5] = {0};
        int fields = sscanf(line, "%llx-%llx %4s %llx %x:%x %llu",
            &start, &end, permissions, &offset, &device_major, &device_minor, &inode);
        if (fields != 7) continue;
        if (device_major != identity->deviceMajor || device_minor != identity->deviceMinor || inode != identity->inode) continue;
        if (start >= end || (permissions[0] != 'r' && permissions[0] != '-')
            || (permissions[1] != 'w' && permissions[1] != '-')
            || (permissions[2] != 'x' && permissions[2] != '-')
            || (permissions[3] != 'p' && permissions[3] != 's')
            || count >= capacity) {
            valid = 0;
            break;
        }
        urp_host_adapter_test_mapping *mapping = &mappings[count++];
        mapping->start = (uint64_t)start;
        mapping->end = (uint64_t)end;
        mapping->offset = (uint64_t)offset;
        mapping->deviceMajor = device_major;
        mapping->deviceMinor = device_minor;
        mapping->inode = (uint64_t)inode;
        memcpy(mapping->permissions, permissions, sizeof(mapping->permissions));
    }
    if (ferror(maps_file) != 0) valid = 0;
    if (fclose(maps_file) != 0) valid = 0;
    if (!valid) return 0;
    *count_out = (uint32_t)count;
    return 1;
}

typedef struct urp_host_adapter_test_rollback_observation {
    uint64_t providerAcquisitions;
    uint64_t consumerDlmopenSuccesses;
    uint64_t bindingVerifications;
    uint64_t failpointReached;
    uint64_t failureConsumerDlcloseCalls;
    uint64_t failureConsumerFdCloseCalls;
    uint64_t providerReleaseCalls;
    int failureConsumerDlcloseResult;
    int failureConsumerFdCloseResult;
    int failureProviderReleaseStatus;
    int failureProviderDlcloseResult;
    int failureProviderFdCloseResult;
    int failureProviderFd;
    int failureConsumerFd;
    uintptr_t failureProviderTableAddress;
    uintptr_t failureProviderLoadBias;
    uintptr_t failureConsumerGotSlotAddress;
    uintptr_t failureConsumerGotValue;
    uintptr_t failureConsumerLoadBias;
    uintptr_t latestProviderTableAddress;
    uintptr_t latestProviderLoadBias;
    uintptr_t latestConsumerGotSlotAddress;
    uintptr_t latestConsumerGotValue;
    uintptr_t latestConsumerLoadBias;
    urp_host_adapter_test_file_identity failureProviderIdentity;
    urp_host_adapter_test_file_identity failureConsumerIdentity;
    urp_host_adapter_test_file_identity latestProviderIdentity;
    urp_host_adapter_test_file_identity latestConsumerIdentity;
    uint32_t failureProviderMappingCount;
    uint32_t failureConsumerMappingCount;
    uint32_t failureMappingCaptureSucceeded;
    uint32_t failureProcessMappingCount;
    urp_host_adapter_test_mapping failureProcessMappings[URP_HOST_ADAPTER_TEST_ROLLBACK_MAX_PROCESS_MAPS];
    urp_host_adapter_test_mapping failureProviderMappings[URP_HOST_ADAPTER_TEST_ROLLBACK_MAX_MAPS];
    urp_host_adapter_test_mapping failureConsumerMappings[URP_HOST_ADAPTER_TEST_ROLLBACK_MAX_MAPS];
    uint32_t eventCount;
    uint32_t events[URP_HOST_ADAPTER_TEST_ROLLBACK_MAX_EVENTS];
    uint32_t eventOverflow;
} urp_host_adapter_test_rollback_observation;

typedef struct urp_host_adapter_test_rollback_state {
    uint64_t activeProviderReferences;
    uint64_t registeredImageCount;
    uint64_t registeredImageDescriptorCount;
    uint64_t activeProviderPresent;
    uint64_t activeProviderDescriptorOpen;
    uint64_t nextImageHandle;
    uint64_t failureProviderDescriptorOpen;
    uint64_t failureConsumerDescriptorOpen;
} urp_host_adapter_test_rollback_state;

void urp_host_adapter_test_arm_provider_binding_failure(void);
void urp_host_adapter_test_rollback_read_observation(
    urp_host_adapter_test_rollback_observation *observation);
void urp_host_adapter_test_rollback_read_state(
    urp_host_adapter_test_rollback_state *state);

#endif
