/*******************************************************************************
 *  Copyright 2012 maidsafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the licence   *
 *  file licence.txt found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ******************************************************************************/

#include <bitset>
#include <memory>
#include <vector>

#include "maidsafe/common/node_id.h"
#include "maidsafe/common/test.h"
#include "maidsafe/common/types.h"

#include "maidsafe/common/log.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/routing/non_routing_table.h"
#include "maidsafe/routing/parameters.h"
#include "maidsafe/rudp/managed_connections.h"
#include "maidsafe/routing/tests/test_utils.h"

namespace maidsafe {
namespace routing {
namespace test {

class BasicNonRoutingTableTest : public testing::Test {
 public:
  BasicNonRoutingTableTest()
     : fob_() {}

 protected:
void SetUp() {
  fob_.identity = Identity(RandomString(64));
}

  Fob fob_;
};

class NonRoutingTableTest : public BasicNonRoutingTableTest {
 public:
  NonRoutingTableTest()
    : nodes_(),
      furthest_close_node_() {}

void PopulateNodes(uint16_t size) {
  for (uint16_t i(0); i < size; ++i)
    nodes_.push_back(MakeNode());
}

void PopulateNodesSetFurthestCloseNode(uint16_t size, const NodeId& target) {
  for (uint16_t i(0); i <= size; ++i)
    nodes_.push_back(MakeNode());
  SortFromTarget(target, nodes_);
  furthest_close_node_ = nodes_.at(size);
  nodes_.pop_back();
}

NodeId BiasNodeIds(std::vector<NodeInfo>& biased_nodes) {
  NodeId sought_id(nodes_.at(RandomUint32() % Parameters::max_non_routing_table_size).node_id);
  for (uint16_t i(0); i < Parameters::max_non_routing_table_size; ++i) {
    if (nodes_.at(i).node_id == sought_id) {
      biased_nodes.push_back(nodes_.at(i));
    } else if ((RandomUint32() % 3) == 0) {
      nodes_.at(i).node_id = sought_id;
      biased_nodes.push_back(nodes_.at(i));
    }
  }
  return sought_id;
}

void ScrambleNodesOrder() {
  SortFromTarget(NodeId(NodeId::kRandomId), nodes_);
}

void PopulateNonRoutingTable(NonRoutingTable& non_routing_table) {
  for (auto node : nodes_)
    EXPECT_TRUE(non_routing_table.AddNode(node, furthest_close_node_.node_id));
}

 protected:
  std::vector<NodeInfo> nodes_;
  NodeInfo furthest_close_node_;
};

TEST_F(BasicNonRoutingTableTest, BEH_CheckAddOwnNodeInfo) {
  NonRoutingTable non_routing_table(fob_);

  NodeInfo node(MakeNode());
  node.node_id = non_routing_table.kNodeId();

  EXPECT_FALSE(non_routing_table.CheckNode(node, NodeId(NodeId::kRandomId)));
  EXPECT_FALSE(non_routing_table.AddNode(node, NodeId(NodeId::kRandomId)));
}

TEST_F(NonRoutingTableTest, BEH_CheckAddFarAwayNode) {
  NonRoutingTable non_routing_table(fob_);

  PopulateNodes(2);

  SortFromTarget(non_routing_table.kNodeId(), nodes_);

  EXPECT_FALSE(non_routing_table.CheckNode(nodes_.at(1), nodes_.at(0).node_id));
  EXPECT_FALSE(non_routing_table.AddNode(nodes_.at(1), nodes_.at(0).node_id));
}

TEST_F(NonRoutingTableTest, BEH_CheckAddSurplusNodes) {
  NonRoutingTable non_routing_table(fob_);

  PopulateNodesSetFurthestCloseNode(2 * Parameters::max_non_routing_table_size,
                                    non_routing_table.kNodeId());
  ScrambleNodesOrder();

  for (int i(0); i < Parameters::max_non_routing_table_size; ++i) {
    EXPECT_TRUE(non_routing_table.CheckNode(nodes_.at(i), furthest_close_node_.node_id));
    EXPECT_TRUE(non_routing_table.AddNode(nodes_.at(i), furthest_close_node_.node_id));
  }

  for (int i(Parameters::max_non_routing_table_size);
       i < 2 * Parameters::max_non_routing_table_size;
       ++i) {
    EXPECT_FALSE(non_routing_table.CheckNode(nodes_.at(i), furthest_close_node_.node_id));
    EXPECT_FALSE(non_routing_table.AddNode(nodes_.at(i), furthest_close_node_.node_id));
  }

  EXPECT_EQ(Parameters::max_non_routing_table_size, non_routing_table.size());
}

TEST_F(NonRoutingTableTest, BEH_CheckAddSameNodeIdTwice) {
  NonRoutingTable non_routing_table(fob_);

  PopulateNodes(2);
  SortFromTarget(non_routing_table.kNodeId(), nodes_);

  EXPECT_TRUE(non_routing_table.CheckNode(nodes_.at(0), nodes_.at(1).node_id));
  EXPECT_TRUE(non_routing_table.AddNode(nodes_.at(0), nodes_.at(1).node_id));

  NodeInfo node(MakeNode());
  node.node_id = nodes_.at(0).node_id;

  EXPECT_EQ(nodes_.at(0).node_id, node.node_id);
  EXPECT_TRUE(non_routing_table.CheckNode(node, nodes_.at(1).node_id));
  EXPECT_TRUE(non_routing_table.AddNode(node, nodes_.at(1).node_id));
}

TEST_F(NonRoutingTableTest, BEH_CheckAddSameConnectionIdTwice) {
  NonRoutingTable non_routing_table(fob_);

  PopulateNodes(3);
  SortFromTarget(non_routing_table.kNodeId(), nodes_);

  EXPECT_TRUE(non_routing_table.CheckNode(nodes_.at(0), nodes_.at(2).node_id));
  EXPECT_TRUE(non_routing_table.AddNode(nodes_.at(0), nodes_.at(2).node_id));

  nodes_.at(1).connection_id = nodes_.at(0).connection_id;

  EXPECT_EQ(nodes_.at(0).connection_id, nodes_.at(1).connection_id);
  EXPECT_TRUE(non_routing_table.CheckNode(nodes_.at(1), nodes_.at(2).node_id));
  EXPECT_FALSE(non_routing_table.AddNode(nodes_.at(1), nodes_.at(2).node_id));
}

TEST_F(NonRoutingTableTest, BEH_CheckAddSameKeysTwice) {
  NonRoutingTable non_routing_table(fob_);

  PopulateNodes(3);
  SortFromTarget(non_routing_table.kNodeId(), nodes_);

  EXPECT_TRUE(non_routing_table.CheckNode(nodes_.at(0), nodes_.at(2).node_id));
  EXPECT_TRUE(non_routing_table.AddNode(nodes_.at(0), nodes_.at(2).node_id));

  nodes_.at(1).public_key = nodes_.at(0).public_key;

  EXPECT_TRUE(asymm::MatchingKeys(nodes_.at(0).public_key, nodes_.at(1).public_key));
  EXPECT_TRUE(non_routing_table.CheckNode(nodes_.at(1), nodes_.at(2).node_id));
  EXPECT_FALSE(non_routing_table.AddNode(nodes_.at(1), nodes_.at(2).node_id));
}

TEST_F(NonRoutingTableTest, BEH_CheckAddSameConnectionAndKeysTwice) {
  NonRoutingTable non_routing_table(fob_);

  PopulateNodes(3);
  SortFromTarget(non_routing_table.kNodeId(), nodes_);

  EXPECT_TRUE(non_routing_table.CheckNode(nodes_.at(0), nodes_.at(2).node_id));
  EXPECT_TRUE(non_routing_table.AddNode(nodes_.at(0), nodes_.at(2).node_id));

  nodes_.at(1).connection_id = nodes_.at(0).connection_id;
  nodes_.at(1).public_key = nodes_.at(0).public_key;

  EXPECT_EQ(nodes_.at(0).connection_id, nodes_.at(1).connection_id);
  EXPECT_TRUE(asymm::MatchingKeys(nodes_.at(0).public_key, nodes_.at(1).public_key));
  EXPECT_TRUE(non_routing_table.CheckNode(nodes_.at(1), nodes_.at(2).node_id));
  EXPECT_FALSE(non_routing_table.AddNode(nodes_.at(1), nodes_.at(2).node_id));
}

TEST_F(NonRoutingTableTest, BEH_AddThenCheckNode) {
  NonRoutingTable non_routing_table(fob_);

  PopulateNodes(2);

  SortFromTarget(non_routing_table.kNodeId(), nodes_);

  EXPECT_TRUE(non_routing_table.CheckNode(nodes_.at(0), nodes_.at(1).node_id));
  EXPECT_TRUE(non_routing_table.AddNode(nodes_.at(0), nodes_.at(1).node_id));
  EXPECT_TRUE(non_routing_table.CheckNode(nodes_.at(0), nodes_.at(1).node_id));
  EXPECT_FALSE(non_routing_table.AddNode(nodes_.at(0), nodes_.at(1).node_id));
}

TEST_F(NonRoutingTableTest, BEH_DropNodes) {
  NonRoutingTable non_routing_table(fob_);

  PopulateNodesSetFurthestCloseNode(Parameters::max_non_routing_table_size,
                                    non_routing_table.kNodeId());
  ScrambleNodesOrder();

  std::vector<NodeInfo> expected_nodes;
  NodeId sought_id(BiasNodeIds(expected_nodes));

  PopulateNonRoutingTable(non_routing_table);

  std::vector<NodeInfo> dropped_nodes(non_routing_table.DropNodes(sought_id));
  EXPECT_EQ(nodes_.size() - dropped_nodes.size(), non_routing_table.size());

  EXPECT_EQ(expected_nodes.size(), dropped_nodes.size());
  bool found_counterpart(false);
  for (auto expected_node : expected_nodes) {
    found_counterpart = false;
    for (auto dropped_node : dropped_nodes) {
      if ((expected_node.connection_id == dropped_node.connection_id) &&
          asymm::MatchingKeys(expected_node.public_key, dropped_node.public_key)) {
        found_counterpart = true;
        break;
      }
    }
    EXPECT_TRUE(found_counterpart);
  }
}

TEST_F(NonRoutingTableTest, BEH_DropConnection) {
  NonRoutingTable non_routing_table(fob_);

  PopulateNodesSetFurthestCloseNode(Parameters::max_non_routing_table_size,
                                    non_routing_table.kNodeId());
  ScrambleNodesOrder();
  PopulateNonRoutingTable(non_routing_table);
  ScrambleNodesOrder();

  while (!nodes_.empty()) {
    NodeInfo dropped_node(non_routing_table.DropConnection(nodes_.at(nodes_.size() - 1).
                                                           connection_id));
    EXPECT_EQ(nodes_.at(nodes_.size() - 1).node_id, dropped_node.node_id);
    EXPECT_EQ(nodes_.at(nodes_.size() - 1).connection_id, dropped_node.connection_id);

    nodes_.pop_back();
    EXPECT_EQ(nodes_.size(), non_routing_table.size());
  }

  EXPECT_EQ(0, non_routing_table.size());
}

TEST_F(NonRoutingTableTest, BEH_GetNodesInfo) {
  NonRoutingTable non_routing_table(fob_);

  PopulateNodesSetFurthestCloseNode(Parameters::max_non_routing_table_size,
                                    non_routing_table.kNodeId());
  ScrambleNodesOrder();

  std::vector<NodeInfo> expected_nodes;
  NodeId sought_id(BiasNodeIds(expected_nodes));

  PopulateNonRoutingTable(non_routing_table);

  std::vector<NodeInfo> got_nodes(non_routing_table.GetNodesInfo(sought_id));

  EXPECT_EQ(expected_nodes.size(), got_nodes.size());
  bool found_counterpart(false);
  for (auto expected_node : expected_nodes) {
    found_counterpart = false;
    for (auto got_node : got_nodes) {
      if ((expected_node.connection_id == got_node.connection_id) &&
          asymm::MatchingKeys(expected_node.public_key, got_node.public_key)) {
        found_counterpart = true;
        break;
      }
    }
    EXPECT_TRUE(found_counterpart);
  }
}

TEST_F(NonRoutingTableTest, BEH_IsConnected) {
  NonRoutingTable non_routing_table(fob_);

  PopulateNodesSetFurthestCloseNode(2 * Parameters::max_non_routing_table_size,
                                    non_routing_table.kNodeId());
  ScrambleNodesOrder();

  for (int i(0); i < Parameters::max_non_routing_table_size; ++i)
    EXPECT_TRUE(non_routing_table.AddNode(nodes_.at(i), furthest_close_node_.node_id));

  for (int i(0); i < Parameters::max_non_routing_table_size; ++i)
    EXPECT_TRUE(non_routing_table.IsConnected(nodes_.at(i).node_id));

  for (int i(Parameters::max_non_routing_table_size);
       i < 2 * Parameters::max_non_routing_table_size;
       ++i)
    EXPECT_FALSE(non_routing_table.IsConnected(nodes_.at(i).node_id));
}

TEST_F(BasicNonRoutingTableTest, BEH_IsThisNodeInRange) {
  NonRoutingTable non_routing_table(fob_);

  std::vector<NodeId> nodes;
  for (int i(0); i < 101; ++i)
    nodes.push_back(NodeId(NodeId::kRandomId));
  SortIdsFromTarget(non_routing_table.kNodeId(), nodes);
  NodeId furthest_close_node_id(nodes.at(50));
  for (int i(0); i < 50; ++i)
    EXPECT_TRUE(non_routing_table.IsThisNodeInRange(nodes.at(i), furthest_close_node_id));
  for (int i(51); i < 101; ++i)
    EXPECT_FALSE(non_routing_table.IsThisNodeInRange(nodes.at(i), furthest_close_node_id));
}

}  // namespace test
}  // namespace routing
}  // namespace maidsafe