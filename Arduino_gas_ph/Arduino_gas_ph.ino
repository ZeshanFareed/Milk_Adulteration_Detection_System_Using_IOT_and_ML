void setup() {
  Serial.begin(9600);

}

void loop() {
  // Read raw values from sensors
  int gas = analogRead(A0);       // Raw gas sensor value
  int phValue = analogRead(A1);      // Raw pH sensor value

  float phCalibrated = -0.00833 * phValue + 10;
  

  // Print the raw sensor values
  Serial.print("Gas: ");
  Serial.print(gas);
  Serial.print(", pH: ");
  Serial.println(phCalibrated);

  delay(3000);
}



