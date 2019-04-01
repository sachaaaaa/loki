#include "service_node_swarm.h"

#undef LOKI_DEFAULT_LOG_CATEGORY
#define LOKI_DEFAULT_LOG_CATEGORY "service_nodes"

#ifdef UNIT_TEST
  #define prod_static
#else
  #define prod_static static
#endif

namespace service_nodes
{
  static uint64_t get_new_swarm_id(std::mt19937_64 &mt, const swarm_snode_map_t &swarm_to_snodes)
  {
    uint64_t id_new;
    do
    {
      id_new = uniform_distribution_portable(mt, UINT64_MAX);
    } while (swarm_to_snodes.count(id_new) != 0);

    return id_new;
  }

  /// The excess is calculated as the total number of snodes above MIN_SWARM_SIZE across all swarms
  prod_static size_t calc_excess(const swarm_snode_map_t &swarm_to_snodes)
  {
    const size_t excess = std::accumulate(swarm_to_snodes.begin(),
                                          swarm_to_snodes.end(),
                                          size_t(0),
                                          [](size_t result, const swarm_snode_map_t::value_type &pair) {
                                            const ssize_t margin = pair.second.size() - EXCESS_BASE;
                                            return result + std::max(margin, ssize_t(0));
                                          });
    LOG_PRINT_L2("Calculated excess: " << excess);
    return excess;
  };

  /// Calculate threshold above which the excess should create a new swarm.
  /// The threshold should be such that
  /// 1. there is enough excess to create a new swarm of size NEW_SWARM_SIZE AND
  /// 2. there is enough excess to leave IDEAL_SWARM_MARGIN excess in the existing swarms
  prod_static size_t calc_threshold(const swarm_snode_map_t &swarm_to_snodes)
  {
    const size_t threshold = NEW_SWARM_SIZE + (swarm_to_snodes.size() * IDEAL_SWARM_MARGIN);
    LOG_PRINT_L2("Calculated threshold: " << threshold);
    return threshold;
  };

  prod_static const excess_pool_snode& pick_from_excess_pool(const std::vector<excess_pool_snode>& excess_pool, std::mt19937_64 &mt)
  {
    /// Select random snode
    const auto idx = uniform_distribution_portable(mt, excess_pool.size());
    return excess_pool.at(idx);
  }

  prod_static bool remove_excess_snode_from_swarm(const excess_pool_snode& excess_snode, swarm_snode_map_t &swarm_to_snodes)
  {
    auto &swarm_sn_vec = swarm_to_snodes.at(excess_snode.swarm_id);
    const size_t original_size = swarm_sn_vec.size();
    swarm_sn_vec.erase(std::remove(swarm_sn_vec.begin(), swarm_sn_vec.end(), excess_snode.public_key), swarm_sn_vec.end());
    return original_size != swarm_sn_vec.size();
  }

  prod_static void get_excess_pool(size_t threshold, swarm_snode_map_t& swarm_to_snodes, std::vector<excess_pool_snode>& pool_snodes, size_t& excess)
  {
    /// Create a pool of all the service nodes belonging
    /// to the swarms that have excess. That way we naturally
    /// make the chances of picking a swarm proportionate to the
    /// swarm size.
    pool_snodes.clear();

    if (threshold < MIN_SWARM_SIZE)
      return;

    excess = 0;
    for (const auto &entry : swarm_to_snodes)
    {
      if (entry.second.size() > threshold)
      {
        excess += entry.second.size() - MIN_SWARM_SIZE;
        for (const auto& sn_pk : entry.second)
        {
          pool_snodes.push_back({sn_pk, entry.first});
        }
      }
    }
  }

  prod_static void create_new_swarm_from_excess(swarm_snode_map_t &swarm_to_snodes, std::mt19937_64 &mt)
  {
    while (calc_excess(swarm_to_snodes) >= calc_threshold(swarm_to_snodes))
    {
      LOG_PRINT_L2("New swarm creation");
      std::vector<crypto::public_key> new_swarm_snodes;

      while (new_swarm_snodes.size() < NEW_SWARM_SIZE)
      {
        std::vector<excess_pool_snode> pool_snodes;
        size_t excess;
        get_excess_pool(EXCESS_BASE, swarm_to_snodes, pool_snodes, excess);
        if (pool_snodes.size() == 0)
        {
          MERROR("Error while getting excess pool for new swarm creation");
          return;
        }
        const auto& random_excess_snode = pick_from_excess_pool(pool_snodes, mt);
        new_swarm_snodes.push_back(random_excess_snode.public_key);
        remove_excess_snode_from_swarm(random_excess_snode, swarm_to_snodes);
      }
      const auto new_swarm_id = get_new_swarm_id(mt, swarm_to_snodes);
      swarm_to_snodes.insert({new_swarm_id, std::move(new_swarm_snodes)});
      LOG_PRINT_L2("Created new swarm from excess: " << new_swarm_id);
    }
  }

  prod_static void calc_swarm_sizes(const swarm_snode_map_t &swarm_to_snodes, std::vector<swarm_size> &sorted_swarm_sizes)
  {
    sorted_swarm_sizes.clear();
    for (const auto &entry : swarm_to_snodes)
    {
      sorted_swarm_sizes.push_back({entry.first, entry.second.size()});
    }
    std::sort(sorted_swarm_sizes.begin(),
              sorted_swarm_sizes.end(),
              [](const swarm_size &a, const swarm_size &b) {
                return a.size < b.size;
              });
  }

  /// Assign each snode from snode_pubkeys into the FILL_SWARM_LOWER_PERCENTILE percentile of swarms
  /// and run the excess/threshold logic after each assignment to ensure new swarms are generated when required.
  prod_static void assign_snodes(const std::vector<crypto::public_key> &snode_pubkeys, swarm_snode_map_t &swarm_to_snodes, std::mt19937_64 &mt)
  {
    std::vector<swarm_size> sorted_swarm_sizes;
    for (const auto &sn_pk : snode_pubkeys)
    {
      calc_swarm_sizes(swarm_to_snodes, sorted_swarm_sizes);
      const size_t percentile_index = FILL_SWARM_LOWER_PERCENTILE * (sorted_swarm_sizes.size() - 1) / 100;
      const size_t percentile_value = sorted_swarm_sizes.at(percentile_index).size;
      /// Find last occurence of percentile_value
      size_t upper_index = sorted_swarm_sizes.size() - 1;
      for (size_t i = percentile_index; i < sorted_swarm_sizes.size(); ++i)
      {
        if (sorted_swarm_sizes[i].size > percentile_value)
        {
          /// Would never happen for i == 0
          upper_index = i - 1;
          break;
        }
      }
      const size_t random_idx = uniform_distribution_portable(mt, upper_index + 1);
      const swarm_id_t swarm_id = sorted_swarm_sizes[random_idx].swarm_id;
      swarm_to_snodes.at(swarm_id).push_back(sn_pk);
      /// run the excess/threshold round after each additional snode
      create_new_swarm_from_excess(swarm_to_snodes, mt);
    }
  }

  void calc_swarm_changes(swarm_snode_map_t &swarm_to_snodes, uint64_t seed)
  {

    if (swarm_to_snodes.size() == 0)
    {
      // nothing to do
      return;
    }

    std::mt19937_64 mersenne_twister(seed);

    std::vector<crypto::public_key> unassigned_snodes;
    const auto it = swarm_to_snodes.find(UNASSIGNED_SWARM_ID);
    if (it != swarm_to_snodes.end()) {
      unassigned_snodes = it->second;
      swarm_to_snodes.erase(it);
    }

    LOG_PRINT_L3("calc_swarm_changes. swarms: " << swarm_to_snodes.size() << ", regs: " << unassigned_snodes.size());

    /// 0. Ensure there is always 1 swarm
    if (swarm_to_snodes.size() == 0)
    {
      const auto new_swarm_id = get_new_swarm_id(mersenne_twister, {});
      swarm_to_snodes.insert({new_swarm_id, {}});
      LOG_PRINT_L2("Created initial swarm " << new_swarm_id);
    }

    /// 1. Assign new registered snodes
    assign_snodes(unassigned_snodes, swarm_to_snodes, mersenne_twister);
    LOG_PRINT_L2("After assignment:");
    for (const auto &entry : swarm_to_snodes)
    {
      LOG_PRINT_L2(entry.first << ": " << entry.second.size());
    }

    /// 2. *Robin Hood Round* steal snodes from wealthy swarms and give them to the poor
    {
      std::vector<swarm_size> sorted_swarm_sizes;
      calc_swarm_sizes(swarm_to_snodes, sorted_swarm_sizes);
      bool insufficient_excess = false;
      for (const auto& swarm : sorted_swarm_sizes)
      {
        /// we have processed all the starving swarms
        if (swarm.size >= MIN_SWARM_SIZE)
          break;

        auto& poor_swarm_snodes = swarm_to_snodes.at(swarm.swarm_id);
        do
        {
          const size_t percentile_index = STEALING_SWARM_UPPER_PERCENTILE * (sorted_swarm_sizes.size() - 1) / 100;
          /// -1 since we will only consider swarm sizes strictly above percentile_value
          size_t percentile_value = sorted_swarm_sizes.at(percentile_index).size - 1;
          percentile_value = std::max(MIN_SWARM_SIZE, percentile_value);
          size_t excess;
          std::vector<excess_pool_snode> excess_pool;
          get_excess_pool(percentile_value, swarm_to_snodes, excess_pool, excess);
          /// If we can't save the swarm, don't bother continuing
          const size_t deficit = MIN_SWARM_SIZE - poor_swarm_snodes.size();
          insufficient_excess = (excess < deficit);
          if (insufficient_excess)
            break;
          const auto& excess_snode = pick_from_excess_pool(excess_pool, mersenne_twister);
          remove_excess_snode_from_swarm(excess_snode, swarm_to_snodes);
          /// Add public key to poor swarm
          poor_swarm_snodes.push_back(excess_snode.public_key);
          LOG_PRINT_L2("Stolen 1 snode from " << excess_snode.public_key << " and donated to " << swarm.swarm_id);
        } while (poor_swarm_snodes.size() < MIN_SWARM_SIZE);

        /// If there is not enough excess for the current swarm,
        /// there isn't either for the next one since the swarms are sorted
        if (insufficient_excess)
          break;
      }
    }

    /// 3. New swarm creation
    create_new_swarm_from_excess(swarm_to_snodes, mersenne_twister);

    /// 4. If there is a swarm with less than MIN_SWARM_SIZE, decommission that swarm.
    if (swarm_to_snodes.size() > 1)
    {
      std::vector<crypto::public_key> decommissioned_snodes;
      for (auto it = swarm_to_snodes.cbegin(); it != swarm_to_snodes.cend();)
      {
        if (it->second.size() < MIN_SWARM_SIZE)
        {
          MWARNING("swarm " << it->first << " is DECOMMISSIONED");
          /// Copy all snode public keys for later
          decommissioned_snodes.insert(decommissioned_snodes.begin(), it->second.begin(), it->second.end());
          /// Remove swarm from map
          it = swarm_to_snodes.erase(it);
        }
        else
        {
          it++;
        }
      }
      /// Assign orphan pubkeys only after the decommissioned swarms has been removed from the map
      if (decommissioned_snodes.size() > 0)
      {
        assign_snodes(decommissioned_snodes, swarm_to_snodes, mersenne_twister);
      }
    }

    /// print
    LOG_PRINT_L2("Swarm outputs:");
    for (const auto &entry : swarm_to_snodes)
    {
      LOG_PRINT_L2(entry.first << ": " << entry.second.size());
    }
  }
}
