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

#ifndef MAIDSAFE_ROUTING_ROUTING_API_IMPL_H_
#define MAIDSAFE_ROUTING_ROUTING_API_IMPL_H_

#include <map>
#include <string>
#include <utility>
#include <vector>

#include "maidsafe/rudp/managed_connections.h"

#include "maidsafe/routing/api_config.h"
#include "maidsafe/routing/message_handler.h"
#include "maidsafe/routing/parameters.h"
#include "maidsafe/routing/routing_table.h"
#include "maidsafe/routing/timer.h"

namespace bs2 = boost::signals2;
namespace fs = boost::filesystem;

namespace maidsafe {

namespace routing {

struct RoutingPrivate {
 public:
  ~RoutingPrivate();

 private:
  RoutingPrivate(const RoutingPrivate&);  // no copy
  RoutingPrivate(const RoutingPrivate&&);  // no move
  RoutingPrivate& operator=(const RoutingPrivate&);  // no assign
  RoutingPrivate(const asymm::Keys &keys, bool client_mode);
  friend class Routing;
  std::shared_ptr<AsioService> asio_service_;
  std::vector<Endpoint> bootstrap_nodes_;
  const asymm::Keys keys_;
  Functors functors_;
  rudp::ManagedConnections rudp_;
  RoutingTable routing_table_;
  Timer timer_;
  std::map<uint32_t, std::pair<std::unique_ptr<boost::asio::deadline_timer>,
                               MessageReceivedFunctor> > waiting_for_response_;
  std::vector<NodeInfo> direct_non_routing_table_connections_;
  // closest nodes to the client.
  MessageHandler message_handler_;
  bool joined_;
  fs::path bootstrap_file_path_;
  bool client_mode_;
};

}  // namespace routing

}  // namespace maidsafe

#endif  // MAIDSAFE_ROUTING_ROUTING_API_IMPL_H_
