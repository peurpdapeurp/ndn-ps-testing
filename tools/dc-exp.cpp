#define BOOST_LOG_DYN_LINK 1

#include <iostream>
#include <random>
#include <unistd.h>
#include <fstream>

#include <ndn-cxx/face.hpp>
#include <ndn-cxx/util/scheduler.hpp>
#include <ndn-cxx/security/key-chain.hpp>
#include <ndn-cxx/security/signing-helpers.hpp>
#include <ndn-cxx/mgmt/nfd/controller.hpp>
#include <ndn-cxx/security/transform/public-key.hpp>
#include <ndn-cxx/ims/in-memory-storage-persistent.hpp>
#include <ndn-cxx/security/command-interest-signer.hpp>

#include <boost/filesystem.hpp>

//#include <PartialSync/logging.hpp>

#include "../src/repo-command-parameter.hpp"
#include "../src/repo-command-response.hpp"

#include <sstream>

#include <algorithm>

using namespace ndn;
using namespace repo;

//_LOG_INIT(DataCollector);

class DeviceSigner
{
public:
  DeviceSigner(std::string& deviceName, Name& prefix, Name repoName, int interval)
  : m_scheduler(m_face.getIoService())
  , m_deviceName(deviceName)
  // /<BigCompany>/<Building1>/<ConfRoom>/sensor/<sensorName>/<sensorType>/<timestamp>
  , m_prefix(Name(prefix).append(m_deviceName)) // Key Name prefix
  , m_repoPrefix(Name("localhost").append(repoName))
  , m_seqFileName("/home/pi/repo-ng/seq/")
  , m_cmdSigner(m_keyChain)
  {
    m_interval = interval;
    m_seq = 0;

    m_seqFileName.append(m_deviceName);
    m_seqFileName.append(".seq");
    initiateSeqFromFile();

    m_face.setInterestFilter(m_prefix,
                           bind(&DeviceSigner::onInterestFromRepo, this, _1, _2),
                           [this] (const Name& prefix) {
			       //_LOG_INFO("Prefix: " << prefix << " successfully registered.");
			       std::cout << "Prefix: " << prefix << " successfully registered." << std::endl;
                             insertFirstData();
                           },
                           [] (const ndn::Name& prefix, const std::string& reason) {
                             std::cerr << "Register failed: " << reason << std::endl;
                           },
                           security::SigningInfo(),
                           nfd::ROUTE_FLAG_CAPTURE);
  }

  void
  initiateSeqFromFile() {
    std::ifstream inputFile(m_seqFileName.c_str());

    std::cout << "Sequence file directory: " << m_seqFileName.c_str() << std::endl;
    
    if (inputFile.good()) {

      uint32_t seqNo = 0;

      inputFile >> seqNo;
      m_seq = seqNo;
    
    } else {
      writeSeqToFile();
    }
    inputFile.close();

    std::cout << "Value of m_seq after initiation: " << m_seq << std::endl;
    
  }

  void writeSeqToFile() {
    std::ofstream outputFile(m_seqFileName.c_str());
    std::ostringstream os;
    os << std::to_string(m_seq);
    outputFile << os.str();
    outputFile.close();
  }

  void
  insertFirstData()
  {
    //_LOG_DEBUG("Inserting first data " << m_temperatureI << " " << m_humidityI);
    std::cout << "Inserting first data: " << m_prefix << std::endl;
    Data data(m_deviceName);
    onData(Interest(m_deviceName), data);
  }

  void
  sendInterest(const Name& interestName)
  {
    Name typeName(m_deviceName);
    typeName.append(interestName.get(interestName.size()-1).toUri());

    std::cout << "Sending interest with name: " << interestName.toUri() << std::endl;

    Interest sensorDataInterest(interestName);
    sensorDataInterest.setMustBeFresh(true);
    
    m_face.expressInterest(sensorDataInterest,
                           bind(&DeviceSigner::onData, this,  _1, _2),
                           [] (const Interest& interest, const ndn::lp::Nack& nack) {
			       //_LOG_INFO("Nack from repo " << nack.getReason());
			       std::cout << "Nack from repo " << nack.getReason() << std::endl;
                           },
                           [] (const Interest& interest) {
			       //_LOG_INFO("Timeout from repo");
			       std::cout << "Timeout from repo" << std::endl;
                           });
  }

  void
  onData(const Interest& interest, const Data& data)
  {
    Name dataName(m_prefix);
    dataName.append(m_repoPrefix);

    dataName.appendNumber(m_seq++);
    writeSeqToFile();

    std::cout << "Data name after appending sequence number: " << dataName.toUri() << std::endl;

    // Prepare data to be inserted into repo
    std::shared_ptr<Data> repoData = std::make_shared<Data>();

    const uint8_t* bufferU = data.getContent().value();
    const char* buffer = reinterpret_cast<const char*> (bufferU);
    const char* end = std::find(buffer, buffer + std::strlen(buffer), '~');
    //std::cout << "Size of buffer: " << std::strlen(buffer) << std::endl;
    std::string contentWithoutTimestamp(buffer, end - 1);
    //std::cout << "Content without timestamp: \n" << contentWithoutTimestamp << std::endl;

    //std::stringstream contentWithoutTimestamp;
    //contentWithoutTimestamp << buffer;
    
    std::string contentWithTimestamp = contentWithoutTimestamp + "\n" +
      time::toString(time::system_clock::now(), "Y%Ym%md%dH%HM%MS%S");

    //std::cout << "Content with timestamp: \n" << contentWithTimestamp << std::endl;

    // /uofm/dunn-hall/sensor/221/temperature/%00
    repoData->setName(dataName);
    repoData->setContent(reinterpret_cast<const uint8_t*>(contentWithTimestamp.data()), contentWithTimestamp.size());
    repoData->setFreshnessPeriod(time::milliseconds(1000));

    // sign by identity: /uofm/dunn-hall/221/sensor/panel1/
    m_keyChain.sign(*repoData);

    std::cout << "Inserting into repo: " << repoData->getName() << std::endl;
    //_LOG_INFO("Inserting into repo: " << repoData->getName())
    std::cout << "Data of repo data being inserted: " << repoData->getContent().value() << std::endl;

    insertIntoRepo(repoData);

    // Schedule fetch
    time::steady_clock::Duration after = ndn::time::milliseconds(m_interval);
    m_scheduler.scheduleEvent(after, std::bind(&DeviceSigner::sendInterest, this, interest.getName()));
  }

  void
  insertIntoRepo(const std::shared_ptr<Data> data) {
    // Insert into in memory persistent storage
    m_ims.insert(*data);

    RepoCommandParameter parameters;
    parameters.setName(data->getName());

    // Generate command interest
    Interest interest;
    Name cmd = m_repoPrefix;
    cmd
    .append("insert")
    .append(parameters.wireEncode());

    interest = m_cmdSigner.makeCommandInterest(cmd);

    interest.setInterestLifetime(time::milliseconds(4000));

    m_face.expressInterest(interest,
                           nullptr,
                           [] (const Interest& interest, const ndn::lp::Nack& nack) {
			       //_LOG_INFO("Nack from repo " << nack.getReason());
			       std::cout << "Nack from repo " << nack.getReason() << std::endl;
                           },
                           [] (const Interest& interest) {
			       //_LOG_INFO("Timeout from repo");
			       std::cout << "Timeout from repo" << std::endl;
                           });
  }

  void
  onInterestFromRepo(const ndn::Name& prefix, const ndn::Interest& interest) {

    std::shared_ptr<const Data> data = m_ims.find(interest.getName());

    if (!data) {
      //_LOG_INFO("Data not found in IMS! " << interest.getName());
      std::cout << "Data not found in IMS! " << interest.getName() << std::endl;
      return;
    }

    //m_ims.
    //_LOG_INFO("Sending data to repo: " << data->getName());
    std::cout << "Sending data to repo: " << data->getName() << std::endl;

    m_face.put(*data);
  }

  void run()
  {
    try {
      m_face.processEvents();
    } catch (std::runtime_error& e) {
      std::cerr << e.what() << std::endl;
      return;
    }
  }

private:
  Face m_face;
  Scheduler m_scheduler;
  KeyChain m_keyChain;

  // Device name is used to create a face to the device
  // Prefix is the prefix of the data name that the device is listening to
  std::string m_deviceName;
  Name m_prefix;
  uint32_t m_seq;
  
  int m_interval;

  ndn::InMemoryStoragePersistent m_ims;
  ndn::Name m_repoPrefix;
  std::string m_seqFileName;
  ndn::security::CommandInterestSigner m_cmdSigner;
};

int main(int argc, char* argv[]) {
  if ( argc != 4 ) {
    std::cout << " Usage: " << argv[0]
              << " <deviceName> <prefix - /Company/building/roomNumber> <repoName>\n";
  }
  else {
    std::string deviceName(argv[1]);
    Name prefix(argv[2]);
    Name repoName(argv[3]);
    DeviceSigner ds(deviceName, prefix, repoName, 10000);
    ds.run();
  }
}
