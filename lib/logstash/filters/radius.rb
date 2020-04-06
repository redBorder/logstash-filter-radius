# encoding: utf-8

require "logstash/filters/base"
require "logstash/namespace"
require "json"
require "time"
require "dalli"
require "yaml"

require_relative "util/location_constant"
require_relative "util/memcached_config"
require_relative "store/store_manager"



class LogStash::Filters::Radius < LogStash::Filters::Base
  include LocationConstant

  config_name "radius"

  config :memcached_server, :validate => :string, :default => "", :required => false

  #Custom constants
  DATASOURCE =  "rb_location"
  
  public
  def register
    @dim_to_druid = [MARKET, MARKET_UUID, ORGANIZATION, ORGANIZATION_UUID, DEPLOYMENT, DEPLOYMENT_UUID, 
                   SENSOR_NAME, SENSOR_UUID, NAMESPACE, SERVICE_PROVIDER, SERVICE_PROVIDER_UUID, NAMESPACE_UUID]
    @memcached_server = MemcachedConfig::servers.first if @memcached_server.empty?
    @memcached = Dalli::Client.new(@memcached_server, {:expires_in => 0})
    @store = @memcached.get(RADIUS_STORE) || {}
    @store_manager = StoreManager.new(@memcached)   
  end

  public
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

    if clientMac then
      clientMac = clientMac.gsub("-", ":").downcase
      toDruid[CLIENT_MAC] =  clientMac
      @dim_to_druid.each { |dimension| toDruid[dimension] = event.get(dimension) if event.get(dimension) }
      toDruid.merge!(enrichment) if enrichment
      
      toDruid[TIMESTAMP] = timestamp ? timestamp : Time.now.utc.to_i 
      toDruid[SENSOR_IP] = sensorIP if sensorIP
      toCache[CLIENT_ID] = clientId if clientId
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
          @logger.debug? and @logger.debug("PUT  client: #{clientMac} - namespace: #{namespace_id} - contents: " + toCache.to_s);
  
        else
          @store[clientMac + namespace_id] = toCache
          @memcached.set(RADIUS_STORE, @store)
          @logger.debug? and @logger.debug("PUT  client: #{clientMac} - namespace: #{namespace_id} - contents: " + toCache.to_s);
        end 
      else
        @store[clientMac + namespace_id] = toCache
        @memcached.set(RADIUS_STORE, @store)
        @logger.debug? and @logger.debug("PUT  client: #{clientMac} - namespace: #{namespace_id} - contents: " + toCache.to_s);
      end
      
      toDruid[TYPE] = "radius"
      toDruid[CLIENT_PROFILE] = "hard"
      toDruid.merge!(toCache)

      store_enrichment = @store_manager.enrich(toDruid) 

      namespace = store_enrichment[NAMESPACE_UUID]
      datasource = (namespace) ? DATASOURCE + "_" + namespace : DATASOURCE

      counterStore = @memcached.get(COUNTER_STORE)
      counterStore = Hash.new if counterStore.nil?
      counterStore[datasource] = counterStore[datasource].nil? ? 0 : (counterStore[datasource] + 1)
      puts ("escribiendo en COUNTER_STORE #{COUNTER_STORE} y esta escribiendo en #{datasource} el valor #{counterStore[datasource]}")
      @memcached.set(COUNTER_STORE,counterStore)


      flowsNumber = @memcached.get(FLOWS_NUMBER)
      flowsNumber = Hash.new if flowsNumber.nil?
      store_enrichment["flows_count"] = flowsNumber[datasource] if flowsNumber[datasource]  
      
      enrichmentEvent = LogStash::Event.new
      store_enrichment.each {|k,v| enrichmentEvent.set(k,v)}

      yield enrichmentEvent
    end #clientMac 
    event.cancel
  end   # def filter
end     # class Logstash::Filter::Radius
