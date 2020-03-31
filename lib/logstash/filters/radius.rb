# encoding: utf-8

require "logstash/filters/base"
require "logstash/namespace"
require "json"
require "time"
require "dalli"

class LogStash::Filters::Radius < LogStash::Filters::Base

  config_name "radius"

  # Constants
  # Common
  NAMESPACE = "namespace"
  NAMESPACE_UUID = "namespace_uuid"
  WIRELESS_OPERATOR="wireless_operator"

  # Radius Specification
  PACKET_SRC_IP_ADDRESS = "Packet-Src-IP-Address";
  USER_NAME_RADIUS = "User-Name";
  OPERATOR_NAME = "Operator-Name";
  AIRESPACE_WLAN_ID = "Airespace-Wlan_Id";
  CALLING_STATION_ID = "Calling-Station-Id";
  ACCT_STATUS_TYPE = "Acct-Status-Type";
  CALLED_STATION_ID = "Called-Station-Id";
  CLIENT_ACCOUNTING_TYPE = "client_accounting_type";

  #Custom
  RADIUS_STORE = "radius"
  DATASOURCE = "rb_location"
  COUNTER_STORE = "counterStore"
  FLOWS_NUMBER = "flowsNumber"
  
  # end of Constants

  public
  def set_stores
    @store = @memcached.get(RADIUS_STORE)
    @store = Hash.new if @store.nil?
  end

  def register
    @store = {}
    @dimToDruid = [MARKET, MARKET_UUID, ORGANIZATION, ORGANIZATION_UUID, DEPLOYMENT, DEPLOYMENT_UUID, 
                   SENSOR_NAME, SENSOR_UUID, NAMESPACE, SERVICE_PROVIDER, SERVICE_PROVIDER_UUID, NAMESPACE_UUID]
    options = {:expires_in => 0}
    @memcached = Dalli::Client.new("localhost:11211", options)
    set_stores
  end

  def filter(event)
    toDruid = {}
    toCache = {}

    pattern = /^([a-fA-F0-9][a-fA-F0-9][:\-][a-fA-F0-9][a-fA-F0-9][:\-][a-fA-F0-9][a-fA-F0-9][:\-][a-fA-F0-9][a-fA-F0-9][:\-][a-fA-F0-9][a-fA-F0-9][:\-][a-fA-F0-9][a-fA-F0-9])[:\-]((.*))?/ 

    sensorIP = event.get(PACKET_SRC_IP_ADDRESS)
    clientId = event.get(USER_NAME_RADIUS)
    operatorName = event.get(OPERATOR_NAME)
    wirelessId = event.get(AIRESPACE_WLAN_ID) 
    clientMac = event.get(CALLING_STATION_ID)
    clientConnection = event.get(ACCT_STATUS_TYPE)
    wirelessStationSSID = event.get(CALLED_STATION_ID)

    enrichment = event.get("enrichment")

    namespace_id = event.get(NAMESPACE_UUID) ? event.get(NAMESPACE_UUID) : ""

    timestamp = event.get(TIMESTAMP)
    if !clientMac.nil? then
      toDruid[CLIENT_MAC, clientMac.downcase!.gsub!("-", ":")]
      @dimToDruid.each { |dimension| toDruid[dimension] = event.get(dimension) if event.get(dimension) }
      toDruid.merge!(enrichment) if enrichment
      
      toDruid[TIMESTAMP] = timestamp ? timestamp : Time.now.utc.to_i 
      toDruid[SENSOR_IP] = sensorIP if sensorIP
      toCache[CLIENT_ID] = clientID if clientID
      toCache[WIRELESS_OPERATOR] = operatorName if operatorName
      toCache[WIRELESS_ID] = wirelessId  if wirelessId

      if wirelessStationSSID then
        matcher = pattern.match(wirelessStationSSID)
        if matcher then
          if matcher.length == 4 then
            mac = matcher[1].downcase.gsub("-",":")
            toCache[WIRELESS_STATION] = mac
            toCache[WIRELESS_ID] = matcher[2]
          elsif matcher.length == 3 then
            mac = matcher[1].downcase.gsub("-",":")
            toCache[WIRELESS_STATION] = mac
          end
        end
      end

      if clientConnection then
        toDruid[CLIENT_ACCOUNTING_TYPE] = clientConnection.downcase
        if clientConnection.eql? "Stop" then
          # funcion de log
          # log.debug("REMOVE  client: {} - namespace: {} - contents: " + toCache, clientMac, namespace_id);
          #@logger.debug("REMOVE  client: {} - namespace: {} - contents: " + toCache, clientMac, namespace_id);
        else
          @store[clientMac + namespace_id] = toCache
          @memcached.set(RADIUS_STORE, @store)
          # funcion de log
          # log.debug("PUT  client: {} - namespace: {} - contents: " + toCache, clientMac, namespace_id);
        end 
      else
        @store[clientMac + namespace_id] = toCache
        @memcached.set(RADIUS_STORE, @store)
        # funcion de log
        # log.debug("PUT  client: {} - namespace: {} - contents: " + toCache, clientMac, namespace_id);
      end
      toDruid[TYPE] = "radius"
      toDruid[CLIENT_PROFILE] = "hard"
      toDruid.merge!(toCache)

      enrichmentEvent = Logstash::Event.new
      toDruid.each {|k,v| enrichmentEvent.set(k,v)}
        
      namespace = event.get(NAMESPACE_UUID)
      datasource = (namespace) ? DATASOURCE + "_" + namespace : DATASOURCE

      counterStore = @memcached.get(COUNTER_STORE)
      counterStore = Hash.new if counterStore.nil?
      counterStore[datasource] = counterStore[datasource].nil? ? 0 : (counterStore[datasource] + 1)
      @memcached.set(COUNTER_STORE,counterStore)

      flowsNumber = @memcached.get(FLOWS_NUMBER)
      flowsNumber = Hash.new if flowsNumber.nil?
      enrichmentEvent["flows_count"] = flowsNumber[datasource] if flowsNumber[datasource]  

      yield enrichmentEvent
      event.cancel
    end #clientMac 
  end   # def filter
end     # class Logstash::Filter::Radius
