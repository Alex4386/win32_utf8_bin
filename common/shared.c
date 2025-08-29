#include <windows.h>
#include <stdio.h>

// Helper function to write a resource to a file
BOOL write_resource_to_file(const char* path, const char* start, const char* end) {
    FILE *file = fopen(path, "wb");
    if (!file) {
        return FALSE;
    }
    size_t size = end - start;
    fwrite(start, 1, size, file);
    fclose(file);
    return TRUE;
}
