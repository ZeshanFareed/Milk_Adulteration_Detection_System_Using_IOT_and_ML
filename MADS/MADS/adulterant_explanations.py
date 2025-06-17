def get_adulterant_explanations():
    """
    Returns a dictionary of detailed explanations for each adulterant type.
    Each entry includes the adulterant name, description, health risks, and detection significance.
    """
    return {
        'Pure Milk': {
            'description': 'Pure milk is free from any adulterants and meets standard quality parameters. It contains natural levels of lactose, fat, protein, and other components without contamination.',
            'health_risks': 'None. Pure milk is safe for consumption and provides essential nutrients like calcium, protein, and vitamins.',
            'detection_significance': 'Confirming milk purity ensures compliance with food safety standards and maintains consumer trust in dairy products.'

        },
        'Urea Adulteration': {
            'description': 'Urea, a nitrogen-rich compound, is added to milk to artificially increase its protein content readings, masking dilution or poor quality.',
            'health_risks': 'Consumption of urea-adulterated milk can lead to kidney damage, digestive issues, and long-term health complications due to its toxicity.',
            'detection_significance': 'Detecting urea prevents health risks and ensures the nutritional integrity of milk, protecting consumers from fraudulent practices.'
        },
        'Starch Adulteration': {
            'description': 'Starch is added to milk to increase its thickness and volume, often to compensate for dilution with water.',
            'health_risks': 'Starch reduces the nutritional value of milk and may cause digestive issues, particularly in individuals with starch intolerance.',
            'detection_significance': 'Identifying starch ensures milk meets quality standards and prevents economic fraud by maintaining product authenticity.'
        },
        'Maltodextrin Adulteration': {
            'description': 'Maltodextrin, a carbohydrate derived from starch, is used to increase milk solids and mimic natural milk composition.',
            'health_risks': 'While generally safe in small amounts, excessive consumption can affect taste, nutritional profile, and may pose risks for diabetic individuals due to its high glycemic index.',
            'detection_significance': 'Detection ensures milk is not misrepresented, preserving its nutritional value and consumer trust.'
        },
        'Sodium Bicarbonate Adulteration': {
            'description': 'Sodium bicarbonate is added to neutralize acidity in spoiled milk, extending its shelf life and masking poor quality.',
            'health_risks': 'Can cause alkalosis, digestive disturbances, and long-term health issues if consumed regularly.',
            'detection_significance': 'Identifying sodium bicarbonate prevents consumption of spoiled or low-quality milk, ensuring safety and quality.'
        },
        'Formaldehyde Adulteration': {
            'description': 'Formaldehyde, a toxic preservative, is illegally added to milk to extend shelf life and prevent spoilage.',
            'health_risks': 'Highly toxic, formaldehyde can cause severe health issues, including respiratory problems, organ damage, and increased cancer risk.',
            'detection_significance': 'Detection is critical to protect public health and prevent the use of hazardous chemicals in food products.'
        },
        'Water Adulteration': {
            'description': 'Water is added to milk to increase its volume, reducing production costs but diluting nutritional content.',
            'health_risks': 'Reduces the nutritional value of milk, potentially leading to inadequate nutrient intake, especially in children.',
            'detection_significance': 'Detecting water adulteration ensures milk meets nutritional standards and prevents economic fraud.'
        }
    }