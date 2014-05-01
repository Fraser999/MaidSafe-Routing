/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

#ifndef MAIDSAFE_ROUTING_API_CONFIG_H_
#define MAIDSAFE_ROUTING_API_CONFIG_H_

#include <functional>
#include <string>
#include <vector>

#include "boost/asio/ip/udp.hpp"

#include "maidsafe/common/rsa.h"
#include "maidsafe/common/node_id.h"
#include "maidsafe/rudp/managed_connections.h"
#include "maidsafe/routing/matrix_change.h"
#include "maidsafe/routing/message.h"

namespace maidsafe {

namespace routing {

struct NodeInfo;

enum class DestinationType : int {
  kDirect = 0,
  kClosest,
  kGroup
};

// FIXME(Team) BEFORE_RELEASE add public key and timestamp to BootstrapContact
typedef boost::asio::ip::udp::endpoint BootstrapContact;

typedef std::vector<BootstrapContact> BootstrapContacts;

typedef std::function<void(std::string)> ResponseFunctor;

// They are passed as a parameter by MessageReceivedFunctor and should be called for responding to
// the received message. Passing an empty message will mean you don't want to reply.
typedef std::function<void(const std::string& /*message*/)> ReplyFunctor;

// This is called on any message received that is NOT a reply to a request made by the Send method.
typedef std::function<void(const std::string& /*message*/,
                           ReplyFunctor /*reply functor*/)> MessageReceivedFunctor;

// This is fired to validate a new peer node. User is supposed to validate the node and call
// ValidateThisNode() method with valid public key.
typedef std::function<void(asymm::PublicKey /*public_key*/)> GivePublicKeyFunctor;
typedef std::function<void(NodeId /*node Id*/, GivePublicKeyFunctor)> RequestPublicKeyFunctor;

typedef std::function<void(const std::string& /*data*/,
                           ReplyFunctor /*reply functor*/)> HaveCacheDataFunctor;
typedef std::function<void(const std::string& /*data*/)> StoreCacheDataFunctor;

// This functor fires a number from 0 to 100 and represents % network health.
typedef std::function<void(int /*network_health*/)> NetworkStatusFunctor;

// This functor fires a validated endpoint which is usable for bootstrapping
typedef std::function<void(const boost::asio::ip::udp::endpoint& /*new_endpoint*/)>
    NewBootstrapEndpointFunctor;

// This functor fires when a new close node is inserted in routing table. Upper layers responsible
// for storing key/value pairs should send all key/values between itself and the new node's address
// to the new node. Keys further than the furthest node can safely be deleted (if any).
typedef std::function<void(const std::vector<NodeInfo>& /*new_close_nodes*/)>
    CloseNodeReplacedFunctor;

typedef std::function<void(std::shared_ptr<MatrixChange> /*matrix_change*/)> MatrixChangedFunctor;

// This functor fires when routing table size is over greedy limit. The furthest unnecessary
// node in routing table is dropped. Unnecessary is defined as a node who does not have us in
// it clsoest nodes.
typedef std::function<void()> RemoveFurthestUnnecessaryNode;

template <typename T>
struct MessageAndCachingFunctorsType {
  std::function<void(const T& /*message*/)> message_received;
  std::function<bool(const T& /*message*/)> get_cache_data;
  std::function<void(const T& /*message*/)> put_cache_data;
};

template <typename T>
struct RelayMessageFunctorType {
  std::function<void(const T& /*message*/)> message_received;
};

struct TypedMessageAndCachingFunctor {  // New API
  MessageAndCachingFunctorsType<SingleToSingleMessage> single_to_single;
  MessageAndCachingFunctorsType<SingleToGroupMessage> single_to_group;
  MessageAndCachingFunctorsType<GroupToSingleMessage> group_to_single;
  MessageAndCachingFunctorsType<GroupToGroupMessage> group_to_group;
  RelayMessageFunctorType<SingleToGroupRelayMessage> single_to_group_relay;
};

struct MessageAndCachingFunctors {
  MessageReceivedFunctor message_received;
  HaveCacheDataFunctor have_cache_data;
  StoreCacheDataFunctor store_cache_data;
};

// Note : Provide TypedMessageAndCachingFunctor for typed message API and MessageAndCachingFunctor
// for string type message API. Providing both (TypedMessageAndCachingFunctor &
// MessageAndCachingFunctor) is not allowed.

struct Functors {
  Functors()
      : message_and_caching(),
        typed_message_and_caching(),
        network_status(),
        close_node_replaced(),
        matrix_changed(),
        set_public_key(),
        request_public_key(),
        new_bootstrap_endpoint() {}

  MessageAndCachingFunctors message_and_caching;
  TypedMessageAndCachingFunctor typed_message_and_caching;
  NetworkStatusFunctor network_status;
  CloseNodeReplacedFunctor close_node_replaced;
  MatrixChangedFunctor matrix_changed;
  GivePublicKeyFunctor set_public_key;
  RequestPublicKeyFunctor request_public_key;
  NewBootstrapEndpointFunctor new_bootstrap_endpoint;
};

}  // namespace routing

}  // namespace maidsafe

#endif  // MAIDSAFE_ROUTING_API_CONFIG_H_
