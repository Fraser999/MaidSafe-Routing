/*  Copyright 2015 MaidSafe.net limited

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

#ifndef MAIDSAFE_ROUTING_CLIENT_H_
#define MAIDSAFE_ROUTING_CLIENT_H_

#include <atomic>
#include <cstdint>
#include <memory>
#include <utility>
#include <vector>

#include "asio/io_service.hpp"
#include "asio/post.hpp"
#include "boost/filesystem/path.hpp"
#include "boost/optional/optional.hpp"

#include "maidsafe/common/asio_service.h"
#include "maidsafe/common/identity.h"
#include "maidsafe/common/make_unique.h"
#include "maidsafe/common/rsa.h"
#include "maidsafe/common/types.h"
#include "maidsafe/common/containers/lru_cache.h"
#include "maidsafe/passport/types.h"

#include "maidsafe/routing/bootstrap_handler.h"
#include "maidsafe/routing/peer_node.h"
#include "maidsafe/routing/sentinel.h"
#include "maidsafe/routing/types.h"
#include "maidsafe/routing/messages/messages_fwd.h"
#include "maidsafe/routing/messages/get_data.h"

namespace maidsafe {

namespace routing {

template <typename Child>
class Client {
 public:
  Client(asio::io_service& io_service, Identity our_id, asymm::Keys our_keys);
  Client(asio::io_service& io_service, const passport::Maid& maid);
  Client(asio::io_service& io_service, const passport::Mpid& mpid);
  Client() = delete;
  Client(const Client&) = delete;
  Client(Client&&) = delete;
  Client& operator=(const Client&) = delete;
  Client& operator=(Client&&) = delete;
  ~Client();

  // Normal bootstrap mechanism
  template <typename CompletionToken>
  BootstrapReturn<CompletionToken> Bootstrap(CompletionToken&& token);
  // Bootstrap off a specific node
  template <typename CompletionToken>
  BootstrapReturn<CompletionToken> Bootstrap(Endpoint endpoint, CompletionToken&& token);
  // Returns a shared_ptr<Data> constructed from the requested derived type.
  template <typename CompletionToken, typename Name>
  GetReturn<CompletionToken> Get(const Data::NameAndTypeId& name_and_type_id,
                                 CompletionToken&& token);
  // will return with allowed or not (error_code only)
  template <typename CompletionToken, typename Name>
  PutReturn<CompletionToken> Put(std::shared_ptr<Data> data, CompletionToken&& token);
  // will return with allowed or not (error_code only)
  template <typename CompletionToken, typename Name>
  PostReturn<CompletionToken> Post(Name name, SerialisedMessage message, CompletionToken&& token);
  Address OurId() const { return our_id_; }

 private:
  void MessageReceived(const Address& peer_id, SerialisedMessage message);
  void ConnectionLost(const Address& peer_id);

  SourceAddress OurSourceAddress() const;

  void OnCloseGroupChanged(CloseGroupDifference close_group_difference);
  void HandleMessage(ConnectResponse&& connect_response);
  void HandleMessage(GetDataResponse&& get_data_response);
  void HandleMessage(routing::Post&& post);
  void HandleMessage(PostResponse&& post_response);

  BoostAsioService crux_asio_service_;
  asio::io_service& io_service_;
  const Address our_id_;
  const asymm::Keys our_keys_;
  std::atomic<MessageId> message_id_;
  boost::optional<Address> bootstrap_node_;
  BootstrapHandler bootstrap_handler_;
  std::vector<PeerNode> connected_peers_;
  LruCache<std::pair<Address, MessageId>, void> filter_;
  Sentinel sentinel_;
};



template <typename Child>
Client<Child>::Client(asio::io_service& io_service, Identity our_id, asymm::Keys our_keys)
    : crux_asio_service_(1),
      io_service_(io_service),
      our_id_(std::move(our_id)),
      our_keys_(std::move(our_keys)),
      message_id_(RandomUint32()),
      bootstrap_node_(),
      bootstrap_handler_(),
      connected_peers_(),
      filter_(std::chrono::minutes(20)),
      sentinel_([](Address) {}, [](GroupAddress) {}) {}

template <typename Child>
Client<Child>::Client(asio::io_service& io_service, const passport::Maid& maid)
    : crux_asio_service_(1),
      io_service_(io_service),
      our_id_(maid.name()),
      our_keys_([&]() -> asymm::Keys {
        asymm::Keys keys;
        keys.private_key = maid.private_key();
        keys.public_key = maid.public_key();
        return keys;
      }()),
      message_id_(RandomUint32()),
      bootstrap_node_(),
      bootstrap_handler_(),
      connected_peers_(),
      filter_(std::chrono::minutes(20)),
      sentinel_([](Address) {}, [](GroupAddress) {}) {}

template <typename Child>
Client<Child>::Client(asio::io_service& io_service, const passport::Mpid& mpid)
    : crux_asio_service_(1),
      io_service_(io_service),
      our_id_(mpid.name()),
      our_keys_([&]() -> asymm::Keys {
        asymm::Keys keys;
        keys.private_key = mpid.private_key();
        keys.public_key = mpid.public_key();
        return keys;
      }()),
      message_id_(RandomUint32()),
      bootstrap_node_(),
      bootstrap_handler_(),
      connected_peers_(),
      filter_(std::chrono::minutes(20)),
      sentinel_([](Address) {}, [](GroupAddress) {}) {}

template <typename Child>
void Client<Child>::MessageReceived(const Address& /*peer_id*/, SerialisedMessage message) {
  InputVectorStream binary_input_stream(std::move(message));
  MessageHeader header;
  MessageTypeTag tag;
  try {
    Parse(binary_input_stream, header, tag);
  } catch (const std::exception&) {
    LOG(kError) << "header failure: " << boost::current_exception_diagnostic_information();
    return;
  }

  if (filter_.Check(header.FilterValue()))
    return;  // already seen
  // add to filter as soon as posible
  filter_.Add(header.FilterValue());

  switch (tag) {
    case MessageTypeTag::ConnectResponse:
      HandleMessage(Parse<ConnectResponse>(binary_input_stream));
      break;
    case MessageTypeTag::GetDataResponse:
      HandleMessage(Parse<GetDataResponse>(binary_input_stream));
      break;
    // case MessageTypeTag::PutDataResponse:
    //   HandleMessage(
    //       Parse<PutDataResponse>(binary_input_stream));
    //   break;
    // case MessageTypeTag::Post:
    //   HandleMessage(Parse<Post>(binary_input_stream));
    //   break;
    // case MessageTypeTag::Request:
    //   HandleMessage(Parse<Request>(binary_input_stream));
    //   break;
    // case MessageTypeTag::Response:
    //   HandleMessage(Parse<MessageTypeTag::Response>(binary_input_stream));
    //   break;
    default:
      LOG(kWarning) << "Received message of unknown type.";
      break;
  }
}

template <typename Child>
void Client<Child>::HandleMessage(ConnectResponse&& /*connect_response*/) {}

template <typename Child>
void Client<Child>::HandleMessage(GetDataResponse&& /*get_data_response*/) {}

template <typename Child>
void Client<Child>::HandleMessage(routing::Post&& /*post*/) {}

template <typename Child>
void Client<Child>::HandleMessage(PostResponse&& /*post_response*/) {}

// void ConnectionLost(NodeId /* peer */) { /*LostNetworkConnection(peer);*/ }

template <typename Child>
SourceAddress Client<Child>::OurSourceAddress() const {
  assert(bootstrap_node_);
  return SourceAddress(NodeAddress(*bootstrap_node_), boost::none, ReplyToAddress(OurId()));
}



template <typename Child>
template <typename CompletionToken>
BootstrapReturn<CompletionToken> Client<Child>::Bootstrap(CompletionToken&& token) {
  BootstrapHandlerHandler<CompletionToken> handler(std::forward<decltype(token)>(token));
  asio::async_result<decltype(handler)> result(handler);
  auto this_ptr(shared_from_this());
  asio::post(io_service_, [=] {
    // TODO(PeterJ)
    //    rudp_.Bootstrap(bootstrap_handler_.ReadBootstrapContacts(), this_ptr, our_id_, our_keys_,
    //                    handler);
  });
  return result.get();
}

template <typename Child>
template <typename CompletionToken>
BootstrapReturn<CompletionToken> Client<Child>::Bootstrap(Endpoint /*local_endpoint*/,
                                                          CompletionToken&& token) {
  BootstrapHandlerHandler<CompletionToken> handler(std::forward<decltype(token)>(token));
  asio::async_result<decltype(handler)> result(handler);
  auto this_ptr(shared_from_this());
  asio::post(io_service_, [=] {
    // TODO(PeterJ)
    //    rudp_.Bootstrap(bootstrap_handler_.ReadBootstrapContacts(), this_ptr, our_id_, our_keys_,
    //                    handler, local_endpoint);
  });
  return result.get();
}

template <typename Child>
template <typename CompletionToken, typename Name>
GetReturn<CompletionToken> Client<Child>::Get(const Data::NameAndTypeId& name_and_type_id,
                                              CompletionToken&& token) {
  GetHandler<CompletionToken> handler(std::forward<decltype(token)>(token));
  asio::async_result<decltype(handler)> result(handler);
  asio::post(io_service_, [=] {
    MessageHeader our_header(std::make_pair(Destination(name_and_type_id.name), boost::none),
                             OurSourceAddress(), ++message_id_, Authority::client);
    GetData request(name_and_type_id, OurSourceAddress());
    auto message(Serialise(our_header, MessageToTag<GetData>::value(), request));
    //    auto targets(connection_manager_.GetTarget(name.value));
    //    for (const auto& target : targets)
    //      connection_manager_.FindPeer(target)->Send(message, [](asio::error_code) {});
  });
  return result.get();
}

template <typename Child>
template <typename CompletionToken, typename Name>
PutReturn<CompletionToken> Client<Child>::Put(std::shared_ptr<Data> data, CompletionToken&& token) {
  PutHandler<CompletionToken> handler(std::forward<decltype(token)>(token));
  asio::async_result<decltype(handler)> result(handler);
  asio::post(asio_service_.service(), [=]() mutable {
    MessageHeader our_header(
        std::make_pair(Destination(OurId()), boost::none),  // send to ClientMgr
        OurSourceAddress(), ++message_id_, Authority::client);
    PutData request(data->TypeId(), Serialise(data));
    // FIXME(Team) this needs signed
    auto message(Serialise(our_header, MessageToTag<PutData>::value(), request));
    auto targets(connection_manager_.GetTarget(OurId()));
    // for (const auto& target : targets) {
    //  connection_manager_.Send(target.id, message, [](asio::error_code) {});
    //}
    // if (targets.empty() && bootstrap_node_) {
    //  connection_manager_.Send(*bootstrap_node_, message,
    //                           [handler](std::error_code ec) mutable { handler(ec); });
    //} else {
    //  handler(make_error_code(RoutingErrors::not_connected));
    //}
  });
  return result.get();
}

template <typename Child>
template <typename CompletionToken, typename Name>
PostReturn<CompletionToken> Client<Child>::Post(Name /*name*/, SerialisedMessage /*message*/,
                                                CompletionToken&& token) {
  PostHandler<CompletionToken> handler(std::forward<decltype(token)>(token));
  asio::async_result<decltype(handler)> result(handler);
  auto this_ptr(shared_from_this());
  //  io_service_.post([=] { this_ptr->DoPost(name, message, handler); });
  return result.get();
}

}  // namespace routing

}  // namespace maidsafe

#endif  // MAIDSAFE_ROUTING_CLIENT_H_
