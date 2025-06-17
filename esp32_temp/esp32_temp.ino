#include <WiFi.h>
#include <Firebase_ESP_Client.h>
#include <OneWire.h>
#include <DallasTemperature.h>
#include <HardwareSerial.h>

// Temperature sensor on GPIO4
#define ONE_WIRE_BUS 4
OneWire oneWire(ONE_WIRE_BUS);
DallasTemperature sensors(&oneWire);

// Serial communication with Arduino
#define ARDUINO_RX 16  // GPIO16 (RX2)
#define ARDUINO_TX 17  // GPIO17 (TX2)
HardwareSerial arduinoSerial(2);  // UART2

// WiFi credentials
const char* WIFI_SSID = "abcde";
const char* WIFI_PASSWORD = "coder1234";

// Firebase credentials
#define FIREBASE_HOST "https://mads-36618-default-rtdb.europe-west1.firebasedatabase.app/"
#define FIREBASE_AUTH "xtWxuLmpN9hsb7q2B9gVIdC1pETnxbHlIFDwrtBV"

// Firebase objects
FirebaseData firebaseData;
FirebaseAuth firebaseAuth;
FirebaseConfig firebaseConfig;

// Function to clean numeric string (keep digits, decimal point, and negative sign)
String cleanNumericString(String str) {
  String result = "";
  for (int i = 0; i < str.length(); i++) {
    char c = str.charAt(i);
    if (isdigit(c) || c == '.' || c == '-') {
      result += c;
    }
  }
  return result;
}

void setup() {
  Serial.begin(115200);
  arduinoSerial.begin(9600, SERIAL_8N1, ARDUINO_RX, ARDUINO_TX);  // Initialize UART
  arduinoSerial.setTimeout(100);  // Set 100ms timeout for serial reads

  // Connect to WiFi
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);  // Fixed: Removed "LambertW"
  Serial.print("Connecting to WiFi");
  while (WiFi.status() != WL_CONNECTED) {
    Serial.print(".");
    delay(1000);
  }
  Serial.println("\nConnected to WiFi!");

  // Firebase initialization
  firebaseConfig.host = FIREBASE_HOST;
  firebaseConfig.signer.tokens.legacy_token = FIREBASE_AUTH;
  Firebase.begin(&firebaseConfig, &firebaseAuth);
  Firebase.reconnectWiFi(true);

  // Initialize temperature sensor
  sensors.begin();
}

void loop() {
  static String input = "";
  while (arduinoSerial.available()) {
    char c = arduinoSerial.read();
    if (c == '\n') {
      if (input.length() > 0) {
        Serial.println("Raw input: " + input);  // Debug print

        // Clean and parse input
        int commaIndex = input.indexOf(',');
        if (commaIndex > 0) {
          // Extract gas value
          String gasStr = input.substring(0, commaIndex);
          gasStr.replace("Gas: ", "");  // Remove "Gas: " if present
          gasStr.trim();  // Remove leading/trailing spaces
          gasStr = cleanNumericString(gasStr);  // Keep only numeric characters

          // Extract pH value
          String phStr = input.substring(commaIndex + 1);
          phStr.replace("pH: ", "");  // Remove "pH: " prefix
          phStr.trim();  // Remove leading/trailing spaces
          phStr = cleanNumericString(phStr);  // Keep only numeric characters

          // Convert to numeric values
          float gasValue = gasStr.toFloat();
          float phCalibrated = phStr.toFloat();

          // Request temperature from DS18B20 sensor
          sensors.requestTemperatures();
          float temperature = sensors.getTempCByIndex(0);

          // Print values for debugging
          Serial.printf("Temp: %.2f°C, Gas: %.2f, pH: %.2f\n", temperature, gasValue, phCalibrated);

          // Send data to Firebase
          if (Firebase.RTDB.setFloat(&firebaseData, "/sensorData/Temperature", temperature)) {
            Serial.println("Temperature sent to Firebase");
          } else {
            Serial.println("Failed to send Temperature: " + firebaseData.errorReason());
          }
          if (Firebase.RTDB.setFloat(&firebaseData, "/sensorData/Gas", gasValue)) {
            Serial.println("Gas sent to Firebase");
          } else {
            Serial.println("Failed to send Gas: " + firebaseData.errorReason());
          }
          if (Firebase.RTDB.setFloat(&firebaseData, "/sensorData/pH", phCalibrated)) {
            Serial.println("pH sent to Firebase");
          } else {
            Serial.println("Failed to send pH: " + firebaseData.errorReason());
          }
        } else {
          Serial.println("Invalid input: No comma found.");
        }
      } else {
        Serial.println("Empty ainput received.");
      }

      input = "";  // Clear input buffer
    } else {
      input += c;  // Accumulate input
    }
  }

  delay(3000);  // Reduced delay to process frequent data
}