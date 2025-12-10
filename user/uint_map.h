#ifndef UINT_MAP_H
#define UINT_MAP_H

#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#define MAP_ENTRIES 1024

template <typename T> struct uint_map_entry {
    uint32_t key;
    T value;
    struct uint_map_entry<T>* next;
};

template <typename T> struct uint_map {
    uint_map_entry<T>* buckets[MAP_ENTRIES];
};

template <typename T> bool map_insert_or_assign(uint_map<T>* map, uint32_t key, T* value) {
    if (value == NULL) {
        return false;
    }

    size_t index = key % MAP_ENTRIES;

    uint_map_entry<T>* current = map->buckets[index];
    while (current != NULL) {
        if (current->key == key) {
            current->value = *value;
            return true;
        }
        current = current->next;
    }

    uint_map_entry<T>* node = (uint_map_entry<T>*)malloc(sizeof(uint_map_entry<T>));
    if (node == NULL) {
        return false;
    }

    node->key = key;
    node->value = *value;
    node->next = map->buckets[index];
    map->buckets[index] = node;

    return true;
}

template <typename T> T* map_find(uint_map<T>* map, uint32_t key) {
    size_t index = key % MAP_ENTRIES;
    uint_map_entry<T>* current = map->buckets[index];

    while (current) {
        if (current->key == key) {
            return &(current->value);
        }

        current = current->next;
    }

    return NULL;
}

template <typename T> void map_erase(uint_map<T>* map, uint32_t key) {
    size_t index = key % MAP_ENTRIES;
    uint_map_entry<T>* current = map->buckets[index];
    uint_map_entry<T>* prev = NULL;

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
