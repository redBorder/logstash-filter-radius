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
    @memcached = Dalli::Client.new(@memcached_server, {:expires_in => 0, :value_max_bytes => 4000000})
    @store = @memcached.get(RADIUS_STORE) || {}
    @store_manager = StoreManager.new(@memcached)   
  end

  public

   def refresh_stores
     return nil unless @last_refresh_stores.nil? || ((Time.now - @last_refresh_stores) > (60 * 5))
     @last_refresh_stores = Time.now
     e = LogStash::Event.new
     e.set("refresh_stores",true)
     return e
  end

  def filter(event)
    to_druid = {}
    to_cache = {}

    pattern = /^([a-fA-F0-9][a-fA-F0-9][:\-][a-fA-F0-9][a-fA-F0-9][:\-][a-fA-F0-9][a-fA-F0-9][:\-][a-fA-F0-9][a-fA-F0-9][:\-][a-fA-F0-9][a-fA-F0-9][:\-][a-fA-F0-9][a-fA-F0-9])[:\-]((.*))?/ 

    sensor_ip = event.get(PACKET_SRC_IP_ADDRESS)
    client_id = event.get(USER_NAME_RADIUS)
    operator_name = event.get(OPERATOR_NAME)
    wirelessId = event.get(AIRESPACE_WLAN_ID) 
    client_mac = event.get(CALLING_STATION_ID)
    client_connection = event.get(ACCT_STATUS_TYPE)
    wireless_station_ssid = event.get(CALLED_STATION_ID)

    enrichment = event.get("enrichment")

    namespace_id = event.get(NAMESPACE_UUID) ? event.get(NAMESPACE_UUID) : ""

    timestamp = event.get(TIMESTAMP)

    if client_mac then
      client_mac = client_mac.gsub("-", ":").downcase
      to_druid[CLIENT_MAC] =  client_mac
      @dim_to_druid.each { |dimension| to_druid[dimension] = event.get(dimension) if event.get(dimension) }
      to_druid.merge!(enrichment) if enrichment
      
      to_druid[TIMESTAMP] = timestamp ? timestamp : Time.now.utc.to_i 
      to_druid[SENSOR_IP] = sensor_ip if sensor_ip
      to_cache[CLIENT_ID] = client_id if client_id
      to_cache[WIRELESS_OPERATOR] = operator_name if operator_name
      to_cache[WIRELESS_ID] = wirelessId  if wirelessId

      if wireless_station_ssid then
        matcher = pattern.match(wireless_station_ssid)
        if matcher then
          if matcher.length == 4 then
            mac = matcher[1].downcase.gsub("-",":")
            to_cache[WIRELESS_STATION] = mac
            to_cache[WIRELESS_ID] = matcher[2]
          elsif matcher.length == 3 then
            mac = matcher[1].downcase.gsub("-",":")
            to_cache[WIRELESS_STATION] = mac
          end
        end
      end

      if client_connection then
        to_druid[CLIENT_ACCOUNTING_TYPE] = client_connection.downcase
        to_cache[CLIENT_ACCOUNTING_TYPE] = client_connection.downcase
        @store[client_mac + namespace_id] = to_cache
        @memcached.set(RADIUS_STORE, @store)
        @logger.debug? and @logger.debug("PUT  client: #{client_mac} - namespace: #{namespace_id} - contents: " + to_cache.to_s)
      else
        @store[client_mac + namespace_id] = to_cache
        @memcached.set(RADIUS_STORE, @store)
        @logger.debug? and @logger.debug("PUT  client: #{client_mac} - namespace: #{namespace_id} - contents: " + to_cache.to_s);
      end
      
      to_druid[TYPE] = "radius"
      to_druid[CLIENT_PROFILE] = "hard"
      to_druid.merge!(to_cache)

      store_enrichment = @store_manager.enrich(to_druid) 

      namespace = store_enrichment[NAMESPACE_UUID]
      datasource = (namespace) ? DATASOURCE + "_" + namespace : DATASOURCE

      counter_store = @memcached.get(COUNTER_STORE)
      counter_store = Hash.new if counter_store.nil?
      counter_store[datasource] = counter_store[datasource].nil? ? 0 : (counter_store[datasource] + 1)
      @memcached.set(COUNTER_STORE,counter_store)


      flows_number = @memcached.get(FLOWS_NUMBER)
      flows_number = Hash.new if flows_number.nil?
      store_enrichment["flows_count"] = flows_number[datasource] if flows_number[datasource]  
      
      enrichment_event = LogStash::Event.new
      store_enrichment.each {|k,v| enrichment_event.set(k,v)}

      yield enrichment_event
    end #client_mac 
    event.cancel

    event_refresh = refresh_stores
    yield event_refresh if event_refresh 
    event.cancel
  end   # def filter
end     # class Logstash::Filter::Radius
