#include <SoftwareSerial.h>
#include <ESP8266WiFi.h>
#include <ESP8266HTTPClient.h>
#include <Wire.h>
#include <Adafruit_Thermal.h>


// WiFi details
const char* ssid = "ssid";
const char* wifi_password = "pw";

// Adafruit thermal printer details
#define TX_PIN D5
#define RX_PIN D6
#define BAUDRATE 19200
SoftwareSerial printerSerial(RX_PIN, TX_PIN);
Adafruit_Thermal printer(&printerSerial);

void setup() {
  // Initialize serial communication
  Serial.begin(9600);

  // Connect to Wi-Fi
  WiFi.begin(ssid, wifi_password);
  while (WiFi.status() != WL_CONNECTED) {
    delay(1000);
    Serial.println("Connecting to WiFi...");
  }
  Serial.println("Connected to WiFi");

  // Initialize Adafruit thermal printer
  printerSerial.begin(BAUDRATE);
  printer.begin();

  printShoppingList(getShoppingList());

  // Create space to rip the paper
  printer.feed(5);
}

void loop() {
  // This sketch only needs to run once, so there's nothing to do in the loop.
}

String getShoppingList() {
  WiFiClient wifiClient;
  HTTPClient httpClient;

  httpClient.begin(wifiClient, "https://url.com");
  httpClient.setAuthorization("username", "password");

  int statusCode = httpClient.GET();

  String payload = "";

  if (statusCode > 0) {
    Serial.println("Sent request");

    if (statusCode == 200) {
      Serial.println("Successful request");
      payload = httpClient.getString();
      Serial.println(payload);
    } else {
      Serial.printf("Error,code was %d", statusCode);
      payload = httpClient.getString();
      Serial.println(payload);
    }
  } else {
    Serial.println("Error on sending request");
  }

  httpClient.end();

  return payload;
}

void printShoppingList(String shoppingList) {
  printer.setLineHeight(24);
  printer.doubleHeightOn();
  printer.doubleWidthOn();
  printer.boldOn();
  printer.println("Shopping list");
  printer.doubleHeightOff();
  printer.doubleWidthOff();
  printer.boldOff();
  printer.feed(1);

  printer.println(shoppingList);
}
