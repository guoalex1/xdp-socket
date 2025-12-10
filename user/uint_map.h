#ifndef UINT_MAP_H
#define UINT_MAP_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#define MAP_ENTRIES 1024

template <typename T> struct Entry {
    uint32_t key;
    T value;
    struct Entry<T>* next;
};

template <typename T> struct UIntMap {
    Entry<T>* buckets[MAP_ENTRIES];
};

template <typename T> bool map_insert_or_assign(UIntMap<T>* map, uint32_t key, T* value) {
    if (value == NULL) {
        return false;
    }

    size_t index = key % MAP_ENTRIES;

    Entry<T>* current = map->buckets[index];
    while (current != NULL) {
        if (current->key == key) {
            current->value = *value;
            return true;
        }
        current = current->next;
    }

    Entry<T>* node = (Entry<T>*)malloc(sizeof(Entry<T>));
    if (node == NULL) {
        return false;
    }

    node->key = key;
    node->value = *value;
    node->next = map->buckets[index];
    map->buckets[index] = node;

    return true;
}

template <typename T> T* map_find(UIntMap<T>* map, uint32_t key) {
    size_t index = key % MAP_ENTRIES;
    Entry<T>* current = map->buckets[index];

    while (current) {
        if (current->key == key) {
            return &(current->value);
        }

        current = current->next;
    }

    return NULL;
}

template <typename T> void map_erase(UIntMap<T>* map, uint32_t key) {
    size_t index = key % MAP_ENTRIES;
    Entry<T>* current = map->buckets[index];
    Entry<T>* prev = NULL;

    while (current != NULL) {
        if (current->key == key) {
            if (prev != NULL) {
                prev->next = current->next;
            } else {
                map->buckets[index] = current->next;
            }

            free(current);
            return;
        }
        prev = current;
        current = current->next;
    }
}

#endif
