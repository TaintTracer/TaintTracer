#pragma once

#include <algorithm>
#include <map>
#include <cstdint>
#include <vector>
#include <debugger/memory/MemoryRegion.h>
#include <debugger/memory/MergingRegionSet.h>
#include <fmt/format.h>

template <typename T>
struct AnnotatedMemoryRegion : MemoryRegion {
    T annotation;

    AnnotatedMemoryRegion(uint64_t s, uint64_t e, T a)
            : MemoryRegion(s, e), annotation(std::move(a)) {};
    AnnotatedMemoryRegion(MemoryRegion r, T a)
            : MemoryRegion(r), annotation(std::move(a)) {};
};

/**
 * A collection of non-overlapping memory regions. Each region is annotated with an instance of
 * type T (typically a shared pointer to avoid making copies when splitting regions).
 * The data structure can also be utilized for registers after a conversion from register name to
 * a starting address (derived from register name) and ending address (derived from register name
 * and register size).
 * When inserting, if neighboring address annotation is equal, they are merged into a larger
 * annotation. Destructor of the newly provided annotation object is called.
 */
template <typename T>
class AnnotatedAddressSpace {
private:
    std::map<uint64_t, AnnotatedMemoryRegion<T>> regions_;
    using iterator = typename decltype(regions_)::iterator;
    using on_resize_t = const std::function<void(T& t, MemoryRegion old, MemoryRegion n)>&;
    using on_split_construction_t = const std::function<T(T& t, MemoryRegion old, MemoryRegion n)>&;

    /**
     * Execute callback for each memory region in the address space that intersect with the provided
     * region.
     */
    void for_each_intersection(const MemoryRegion &r, std::function<void(iterator it)> cb) {
        auto assert_intersection = [&] (MemoryRegion r1, MemoryRegion r2) {
            if (!intersects(r1, r2).has_value()) {
                auto regions = std::vector<std::string> {};
                for (const auto &[key, val] : regions_) {
                    assert(key == val.start_address);
                    regions.push_back(val.str());
                }
                throw std::runtime_error(fmt::format("Region {} does not intersect {}. Memory region dump: {}", r1.str(), r2.str(), fmt::join(regions, ", ")));
            }
        };
        if(regions_.empty() || r.end_address - r.start_address == 0)
            return;
        auto it = regions_.upper_bound(r.start_address);
        if (it != regions_.begin()) {
            it--;
            /**
             * it points to the region with the largest starting address that doesn't exceed r's
             * starting address
             */
            if (it->second.end_address > r.start_address) {
                // it intesects with r
                cb(it);
                assert_intersection(it->second, r);
            }
            it++;
        }
        /**
         * it points to a region of memory that is either intersecting with r, or it has a starting
         * address greater or equal to the end address of r
         */
        for (; it != regions_.end() && it->second.start_address < r.end_address; it++) {
            cb(it);
            assert_intersection(it->second, r);
        }
    }
public:
    /**
     * Inserts an annotated region into the address space.
     * If an existing region E intersects with the to-be-inserted region N, E will be:
     * - removed if the N encloses E
     * - split into 1 (E will be resized) or 2 new regions if N overlaps with, but not encloses E
     * After inserting, direct neighbors (without an empty interval between them) with equal region
     * annotations will be merged into 1 region.
     * TODO: Add perfect forwarding with type constraints on U
     * @param new_region Region to insert.
     */
    T& insert(AnnotatedMemoryRegion<T> new_region, on_resize_t on_resize = {}, on_split_construction_t on_split_construction = {}) {
        if (new_region.start_address >= new_region.end_address)
            throw std::invalid_argument("Region must have a smaller start address than its end address");
        auto hint = erase(new_region, on_resize, on_split_construction);
        return regions_.emplace_hint(hint, std::make_pair(new_region.start_address, std::move(new_region)))->second.annotation;
        // TODO: merge neighboring types
    }

    /**
     * @param region_to_erase Region to erase
     * @return Iterator pointing to the element after the starting address of the region to erase
     */
    iterator erase(const MemoryRegion &region_to_erase,
            on_resize_t on_resize = {},
            on_split_construction_t on_split_construction = {}) {
        if(regions_.empty())
            return regions_.begin();
        iterator it;
        // Find regions that start within the new region
        it = regions_.lower_bound(region_to_erase.start_address);
        while (it != regions_.end() && it->second.start_address < region_to_erase.end_address) {
            if (it->second.end_address <= region_to_erase.end_address) {
                // Remove enclosing regions
                it = regions_.erase(it); // it points to the next element
                continue;
            } else {
                // N partially encloses E
                // Modify both the key and start_address field, as they must be kept in sync
                auto shrunken = regions_.extract(it);
                if (on_resize) {
                    on_resize(shrunken.mapped().annotation,
                            MemoryRegion(shrunken.mapped()),
                            MemoryRegion(region_to_erase.end_address, shrunken.mapped().end_address)
                            );
                }
                shrunken.key() = shrunken.mapped().start_address = region_to_erase.end_address;
                auto nrt = regions_.insert(std::move(shrunken));
                it = nrt.position;
                if (!nrt.inserted) {
                    throw std::runtime_error("Error while shrinking partially enclosed region: starting address already exists");
                }
            }
        }
        // it points to the first element with a starting address greater or equal than
        // the ending address of the new region
        if (it == regions_.begin())
            return it;
        it--; // Go to region before the to-be-inserted I
        /**
         * The element to the left of I (which it points to) can be one of the following things:
         *  - disjoint
         *  - intersecting with I, from the start of I up until a point inside I, but not fully enclosing I
         *  - fully enclosing I
         */
        if (!regions_.empty() && region_to_erase.start_address < it->second.end_address) {
            // E intersects I
            if(region_to_erase.end_address < it->second.end_address) {
                // E encloses I, split right side of E
                bool inserted;
                if (on_split_construction) {
                    std::tie(std::ignore, inserted) =
                            regions_.try_emplace(region_to_erase.end_address,
                                                 region_to_erase.end_address,
                                                 it->second.end_address,
                                                 on_split_construction(
                                                         it->second.annotation,
                                                         MemoryRegion(it->second),
                                                         MemoryRegion(region_to_erase.end_address,
                                                                      it->second.end_address)
                                                 )
                            );
                } else {
                    if constexpr (std::is_copy_constructible<T>::value) {
                        std::tie(std::ignore, inserted) = regions_.try_emplace(
                                region_to_erase.end_address,
                                region_to_erase.end_address, it->second.end_address,
                                it->second.annotation);
                    } else {
                        throw std::runtime_error("T is not copy constructable and no on_split_construction callback provided");
                    }
                }

                if (!inserted) {
                    throw std::runtime_error("starting address already exists");
                }
            }
            if (on_resize) {
                on_resize(it->second.annotation,
                          MemoryRegion(it->second),
                          MemoryRegion(it->second.start_address, region_to_erase.start_address)
                );
            }
            it->second.end_address = region_to_erase.start_address; // Resize region to the left of I
        }
        if (it != regions_.end())
            it++;
        return it;
    }

    bool empty() {
        return regions_.empty();
    }

    /**
     * @param r The region to intersect with
     * @return Number of intersecting memory regions in the address space with r
     */
    int num_intersections(const MemoryRegion& r) {
        int num_intersections = 0;
        for_each_intersection(r, [&num_intersections](iterator it) {
            num_intersections++;
        });
        return num_intersections;
    }

    /**
     * Get all annotations for any memory regions that intersect with [start_address,end_address)
     * @param start_address Starting address
     * @param end_address Ending address
     * @return Annotations that intersect with the provided region of memory
     */
    std::vector<std::reference_wrapper<T>> get_annotations(const MemoryRegion& r) {
        std::vector<std::reference_wrapper<T>> annotations;
        for_each_intersection(r, [&](iterator annotated_region) {
            annotations.push_back(annotated_region->second.annotation);
        });
        return annotations;
    }

    std::vector<MemoryRegion> get_intersecting_regions(const MemoryRegion &r) {
        auto res = std::vector<MemoryRegion> {};
        for_each_intersection(r, [&](iterator annotated_region) {
            res.push_back(annotated_region->second);
        });
        return res;
    }

    std::vector<std::reference_wrapper<AnnotatedMemoryRegion<T>>> get_intersecting_items(const MemoryRegion &r) {
        auto res = std::vector<std::reference_wrapper<AnnotatedMemoryRegion<T>>> {};
        for_each_intersection(r, [&](iterator annotated_region) {
            res.push_back(annotated_region->second);
        });
        return res;
    }

    /**
     * @return All elements with its associated memory region
     */
    std::vector<std::reference_wrapper<AnnotatedMemoryRegion<T>>> get_all() {
        auto res = std::vector<std::reference_wrapper<AnnotatedMemoryRegion<T>>> {};
        res.reserve(regions_.size());
        for_each_intersection(MemoryRegion::domain(), [&](iterator annotated_region) {
            res.push_back(annotated_region->second);
        });
        return res;
    }

    /**
     * @return True if the given region is fully mapped by the address space
     */
    bool is_superset(MemoryRegion query) {
        MergingRegionSet s;
        for (const auto r : get_intersecting_regions(query)) {
            s.insert(r);
        }
        if (auto merged_intersections = s.get_all(); merged_intersections.size() == 1) {
            auto r = merged_intersections[0];
            return r.start_address <= query.start_address && query.end_address <= query.end_address;
        }
        return false;
    }

    unsigned long size() {
        return regions_.size();
    }

    uint64_t total_region_size() {
        uint64_t region_size = 0;
        for (const auto &[k, v] : regions_) {
            region_size += v.size();
        }
        return region_size;
    }
};
