#define BOOST_LOG_DYN_LINK 1

#include "../src/repo-command-parameter.hpp"
#include "../src/repo-command-response.hpp"
#include <iostream>

//#include <PartialSync/logging.hpp>

#include <ndn-cxx/encoding/block-helpers.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/util/notification-subscriber.hpp>
#include <ndn-cxx/util/scheduler.hpp>
#include <ndn-cxx/security/command-interest-signer.hpp>

#include <ChronoSync/socket.hpp>

using namespace ndn;
using namespace repo;

//LOG_INIT(ChronoApp);

class ChronoApp
{
public:
  ChronoApp(Name pubSubGroupPrefix, Name repoName)
  : m_pubSubGroupPrefix(pubSubGroupPrefix)
  , m_repoName(repoName)
  // /<group-prefix>/repo1/chronosync
  , m_chronoSyncUserPrefix(Name(pubSubGroupPrefix).append(repoName))
  // /<group-prefix>/chronosync - multicast
  , m_chronoSyncPrefix(Name("chronosync"))
  , m_face(m_ioService)
  , m_scheduler(m_ioService)
  // /localhost/repo1/datastream/insert
  , m_subscriber(m_face, Name("localhost").append("datastream").append(repoName).append("insert"))
  , m_cmdSigner(m_keyChain)
  {
  }

  ~ChronoApp() {
    m_connection.disconnect();
  }

public:
  void run()
  {
    initializeSyncRepo();

    try {
      m_face.processEvents();
    } catch (std::runtime_error& e) {
      std::cerr << e.what() << std::endl;
      return;
    }
  }

protected:
  void initializeSyncRepo()
  {
    m_chronoSyncSocket =
      std::make_shared<chronosync::Socket>(m_chronoSyncPrefix, m_chronoSyncUserPrefix, m_face,
                                           std::bind(&ChronoApp::onChronoSyncUpdate, this, _1));

    m_connection = m_subscriber.onNotification.connect(std::bind(&ChronoApp::onUpdateFromRepo, this, _1));
    m_subscriber.start();
  }

  void
  onChronoSyncUpdate(const std::vector<chronosync::MissingDataInfo>& v) {
    for (auto ms : v) {
      std::string prefix = ms.session.getPrefix(-1).toUri();

      // Check for our own update like NLSR
      if (prefix == m_chronoSyncUserPrefix.toUri()) {
        continue;
      }

      int seq1 = ms.low;
      int seq2 = ms.high;

      for (int i = seq1; i <= seq2; i++) {
        //_LOG_INFO("ChronoSync Update: " << prefix << "/" << i);
	std::cout << "ChronoSync Update: " << prefix << "/" << i << std::endl;
        fetchData(ms.session, i, 3);
      }
    }
  }

  void
  fetchData(const Name& sessionName, const uint64_t& seqNo,
            int nRetries)
  {
    Name interestName;
    interestName.append(sessionName).appendNumber(seqNo);

    Interest interest(interestName);
    //interest.setMustBeFresh(true);
    //_LOG_INFO("Fetching data for : " << interest.getName() << " " << interest.getNonce());
    std::cout << "Fetching data for : " << interest.getName() << " " << interest.getNonce() << std::endl;

    m_face.expressInterest(interest,
                           std::bind(&ChronoApp::onData, this, _1, _2),
                           std::bind(&ChronoApp::onNack, this, _1, _2, nRetries),
                           std::bind(&ChronoApp::onTimeout, this, _1, nRetries));
  }

  void
  onData(const Interest& interest, const Data& data)
  {
    Name ds;
    // Content is the name
    ds.wireDecode(data.getContent().blockFromValue());

    // Get seqNumber from the data Name
    uint32_t seq = ds.get(ds.size()-1).toNumber();

    //_LOG_INFO("ChronoSync DS Update: " << ds.getPrefix(-1) << "/" << seq);
    std::cout << "ChronoSync DS Update: " << ds.getPrefix(-1) << "/" << seq << std::endl;
    insertIntoRepo(ds);
  }

  void
  onNack(const Interest& interest, const lp::Nack& nack, int nRetries)
  {
    //_LOG_INFO("Nack: " << interest.getName() << " " << interest.getNonce());
    std::cout << "Nack: " << interest.getName() << " " << interest.getNonce() << std::endl;
  }

  void
  onTimeout(const Interest& interest, int nRetries)
  {
    //_LOG_INFO("Timeout for interest: " << interest.getName() << " " << interest.getNonce());
    std::cout << "Timeout for interest: " << interest.getName() << " " << interest.getNonce() << std::endl;
    if (nRetries <= 0)
      return;

    Interest newNonceInterest(interest);
    newNonceInterest.refreshNonce();

    m_face.expressInterest(newNonceInterest,
                           std::bind(&ChronoApp::onData, this, _1, _2),
                           std::bind(&ChronoApp::onNack, this, _1, _2, nRetries-1),
                           std::bind(&ChronoApp::onTimeout, this, _1, nRetries-1)
                           );
  }

  void
  insertIntoRepo(const Name& dataName) {
    try {
      std::string dataType = dataName.at(dataName.size()-2).toUri();
      if (dataType == "temperature" || dataType == "light" || dataType == "humidity") {}
      else {
        return;
      }
    } catch (const std::exception& e) {
      std::cout << e.what() << std::endl;
      return;
    }

    //_LOG_INFO("Inserting data into repo: " << dataName);
    std::cout << "Inserting data into repo: " << dataName << std::endl;

    //nameVector.push_back(dataName);

    RepoCommandParameter parameters;
    parameters.setName(dataName);

    // Generate command interest
    Interest interest;
    Name cmd(ndn::Name("localhost").append(m_repoName));
    cmd
    .append("insert")
    .append(parameters.wireEncode());

    interest = m_cmdSigner.makeCommandInterest(cmd);

    interest.setInterestLifetime(time::milliseconds(4000));

    m_face.expressInterest(interest,
                           nullptr,
                           nullptr, // Nack
                           nullptr);
  }

  void
  onUpdateFromRepo(const Data& data) {
    // Repo makes sure it streams only its own update
    Name comp = data.getName();
    std::cout << comp << std::endl;
    for (size_t i = 0; i < comp.size(); i++) {
      if (comp.at(i) == m_repoName.at(0)) {
        // update is from our own repo, safe to publish
        //_LOG_INFO("ChronoSync Publish: " << data.getName());
	std::cout << "ChronoSync Publish: " << data.getName() << std::endl;

        m_chronoSyncSocket->publishData(data.getName().wireEncode(),
                                        time::milliseconds(1000),
                                        m_chronoSyncUserPrefix);
        return;
      }
    }
  }

protected:
  Name m_pubSubGroupPrefix;
  Name m_repoName;

  Name m_chronoSyncUserPrefix;
  Name m_chronoSyncPrefix;

  boost::asio::io_service m_ioService;
  Face m_face;
  util::Scheduler m_scheduler;
  KeyChain m_keyChain;

  std::shared_ptr<chronosync::Socket> m_chronoSyncSocket;

  // Notification from Repo
  util::NotificationSubscriber<Data> m_subscriber;
  util::signal::Connection m_connection;
  std::vector<Name> nameVector;
  ndn::security::CommandInterestSigner m_cmdSigner;
};

int main(int argc, char* argv[]) {
  if ( argc != 3 ) {
    std::cout << " Usage: " << argv[0]
              << " <pub-sub group prefix> <repoName>\n";
  }
  else {
    Name group(argv[1]);
    ChronoApp ChronoApp(group, Name(argv[2]));
    ChronoApp.run();
  }
}
