const mongoose = require('mongoose');
const path = require('path');

// Load environment variables
require('dotenv').config({ path: path.join(__dirname, '../.env') });

// Indian cities with coordinates
const INDIA_LOCATIONS = [
  { city: 'Delhi', ll: [28.6139, 77.2090] },
  { city: 'Mumbai', ll: [19.0760, 72.8777] },
  { city: 'Bangalore', ll: [12.9716, 77.5946] },
  { city: 'Hyderabad', ll: [17.3850, 78.4867] },
  { city: 'Chennai', ll: [13.0827, 80.2707] },
  { city: 'Kolkata', ll: [22.5726, 88.3639] },
  { city: 'Pune', ll: [18.5204, 73.8567] },
  { city: 'Ahmedabad', ll: [23.0225, 72.5714] },
  { city: 'Jaipur', ll: [26.9124, 75.7873] },
  { city: 'Lucknow', ll: [26.8467, 80.9462] },
];

// Attack Schema (inline for script)
const attackSchema = new mongoose.Schema({
  timestamp: Date,
  attackType: String,
  sourceIp: String,
  userAgent: String,
  targetEndpoint: String,
  httpMethod: String,
  payload: mongoose.Schema.Types.Mixed,
  headers: mongoose.Schema.Types.Mixed,
  severity: String,
  blocked: Boolean,
  country: String,
  geolocation: {
    country: String,
    city: String,
    ll: [Number]
  }
});

const Attack = mongoose.model('AttackLog', attackSchema);

async function addGeolocationToAttacks() {
  try {
    // Connect to MongoDB
    const mongoUri = process.env.MONGODB_URI || 'mongodb://localhost:27017/honeypot';
    console.log('🔌 Connecting to MongoDB...');
    
    await mongoose.connect(mongoUri);
    console.log('✅ Connected to MongoDB');

    // Find all attacks without proper geolocation
    const attacks = await Attack.find({ 
      $or: [
        { geolocation: null },
        { geolocation: { $exists: false } },
        { 'geolocation.ll': null },
        { 'geolocation.country': { $ne: 'India' } }
      ]
    });

    console.log(`📊 Found ${attacks.length} attacks to update`);

    if (attacks.length === 0) {
      console.log('✅ All attacks already have India geolocation!');
      await mongoose.connection.close();
      process.exit(0);
    }

    let updatedCount = 0;

    for (const attack of attacks) {
      // Pick a random Indian city
      const location = INDIA_LOCATIONS[Math.floor(Math.random() * INDIA_LOCATIONS.length)];
      
      // Update the attack
      attack.country = 'India';
      attack.geolocation = {
        country: 'India',
        city: location.city,
        ll: location.ll
      };

      await attack.save();
      updatedCount++;

      if (updatedCount % 5 === 0) {
        console.log(`✅ Updated ${updatedCount}/${attacks.length} attacks...`);
      }
    }

    console.log(`\n🎉 Successfully updated ${updatedCount} attacks with India geolocation!`);

    // Show statistics
    const indiaCount = await Attack.countDocuments({ 'geolocation.country': 'India' });
    const cityBreakdown = await Attack.aggregate([
      { $match: { 'geolocation.country': 'India' } },
      { $group: { _id: '$geolocation.city', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    console.log(`\n📊 Total attacks in India: ${indiaCount}`);
    console.log('\n🏙️  Breakdown by city:');
    cityBreakdown.forEach(city => {
      console.log(`   ${city._id}: ${city.count} attacks`);
    });

    // Show sample
    const sampleAttacks = await Attack.find({ 'geolocation.country': 'India' }).limit(3);
    console.log('\n📍 Sample attacks:');
    sampleAttacks.forEach((attack, i) => {
      console.log(`   ${i + 1}. ${attack.attackType} from ${attack.geolocation.city} [${attack.geolocation.ll}]`);
    });

    await mongoose.connection.close();
    console.log('\n✅ Database connection closed');
    console.log('\n🔥 Now refresh your React app to see the heatmap!');
    process.exit(0);
  } catch (error) {
    console.error('❌ Error:', error);
    await mongoose.connection.close();
    process.exit(1);
  }
}

addGeolocationToAttacks();