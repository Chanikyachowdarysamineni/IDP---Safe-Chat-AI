import { pipeline } from '@huggingface/transformers';

type HFResult = Array<{ label: string; score: number }>;

let toxicityClassifier: ((text: string) => Promise<unknown>) | null = null;
let emotionClassifier: ((text: string) => Promise<unknown>) | null = null;
let sentimentClassifier: ((text: string) => Promise<unknown>) | null = null;

// Initialize advanced ML models with automatic device detection
const initModels = async () => {
  if (!toxicityClassifier) {
    console.log('Loading toxicity detection model...');
    try {
      toxicityClassifier = (await pipeline(
        'text-classification',
        'Xenova/toxic-bert',
        { 
          dtype: 'q8',
          device: 'webgpu'
        }
      )) as unknown as ((text: string) => Promise<unknown>);
      console.log('✓ Toxicity model loaded successfully');
    } catch (error) {
      console.warn('WebGPU failed, falling back to WASM:', error);
      toxicityClassifier = (await pipeline(
        'text-classification',
        'Xenova/toxic-bert',
        { dtype: 'q8' }
      )) as unknown as ((text: string) => Promise<unknown>);
    }
  }
  
  if (!emotionClassifier) {
    console.log('Loading emotion detection model...');
    try {
      // Using a proper emotion classification model
      emotionClassifier = (await pipeline(
        'text-classification',
        'Xenova/distilbert-base-uncased-emotion',
        { 
          dtype: 'q8',
          device: 'webgpu'
        }
      )) as unknown as ((text: string) => Promise<unknown>);
      console.log('✓ Emotion model loaded successfully');
    } catch (error) {
      console.warn('Emotion model failed, will use rule-based fallback:', error);
  emotionClassifier = null;
    }
  }

  if (!sentimentClassifier) {
    console.log('Loading sentiment analysis model...');
    try {
      sentimentClassifier = (await pipeline(
        'sentiment-analysis',
        'Xenova/distilbert-base-uncased-finetuned-sst-2-english',
        { 
          dtype: 'q8',
          device: 'webgpu'
        }
      )) as unknown as ((text: string) => Promise<unknown>);
      console.log('✓ Sentiment model loaded successfully');
    } catch (error) {
      console.warn('Sentiment model failed, will use fallback');
      sentimentClassifier = null;
    }
  }
};

export const analyzeMessage = async (text: string) => {
  // Prefer server-side analysis if available (centralized model or HF proxy)
  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ text }),
    });
    if (res.ok) {
      const json = await res.json();
      // server returns { data: { is_abusive, abuse_score, abuse_type, emotions, severity } }
      if (json?.data) {
        const d = json.data;
        // normalize shapes to existing frontend format
        return {
          isAbusive: !!d.is_abusive || !!d.isAbusive,
          abuseScore: d.abuse_score ?? d.abuseScore ?? 0,
          abuseType: d.abuse_type ?? d.abuseType ?? null,
          emotions: (d.emotions || d.emotion || []).map((e: any) => ({ label: e.label ?? e[0], score: e.score ?? e[1] ?? 0 })),
          severity: d.severity || 'safe',
        };
      }
    }
  } catch (err) {
    // ignore and fall back to client-side analysis
  }

  try {
    // Initialize models if not already loaded
    await initModels();

    // Parallel analysis for better performance
    const [rawToxicityResult, rawEmotionResult, rawSentimentResult] = await Promise.all([
      toxicityClassifier ? toxicityClassifier(text) : Promise.resolve(null),
      emotionClassifier ? emotionClassifier(text) : Promise.resolve(null),
      sentimentClassifier ? sentimentClassifier(text) : Promise.resolve(null),
    ]);

    const toxicityResult = (rawToxicityResult as HFResult) || [];
    const emotionResult = (rawEmotionResult as HFResult) || null;
    const sentimentResult = (rawSentimentResult as HFResult) || null;

    // Analyze toxicity with enhanced detection
    const toxicityScore = toxicityResult?.[0]?.score ?? 0;
    const toxicLabel = toxicityResult?.[0]?.label;
    
    // Enhanced abuse detection considering multiple factors
    let adjustedToxicityScore = toxicityScore;
    
    // Boost score if sentiment is very negative
    if (sentimentResult && sentimentResult[0].label === 'NEGATIVE') {
      adjustedToxicityScore = Math.min(1, toxicityScore * 1.15);
    }

    const isAbusive = adjustedToxicityScore > 0.45; // Lower threshold for better detection

    // Determine abuse type with more granularity
    let abuseType = undefined;
    if (isAbusive) {
      if (adjustedToxicityScore > 0.85) {
        abuseType = 'Severe Harassment';
      } else if (adjustedToxicityScore > 0.7) {
        abuseType = 'Harassment';
      } else if (adjustedToxicityScore > 0.55) {
        abuseType = 'Hostile Language';
      } else {
        abuseType = 'Potentially Toxic';
      }
    }

    // Use ML-based emotion detection if available, otherwise fallback
    let emotions;
    if (emotionResult && Array.isArray(emotionResult)) {
      emotions = emotionResult.map(e => ({
        label: e.label.toLowerCase(),
        score: e.score
      }));
    } else {
      emotions = generateEmotions(text, adjustedToxicityScore);
    }

    // Enhanced severity calculation
    let severity: 'safe' | 'low' | 'medium' | 'high' = 'safe';
    
    // Consider both toxicity and emotional intensity
    const maxEmotionScore = Math.max(...emotions.map(e => e.score));
    const combinedScore = (adjustedToxicityScore * 0.7) + (maxEmotionScore * 0.3);
    
    if (combinedScore > 0.8 || adjustedToxicityScore > 0.85) {
      severity = 'high';
    } else if (combinedScore > 0.65 || adjustedToxicityScore > 0.7) {
      severity = 'medium';
    } else if (combinedScore > 0.45 || adjustedToxicityScore > 0.45) {
      severity = 'low';
    }

    return {
      isAbusive,
      abuseScore: adjustedToxicityScore,
      abuseType,
      emotions,
      severity,
    };
  } catch (error) {
    console.error('ML Analysis error:', error);
    
    // Fallback to rule-based analysis
    const simpleAnalysis = simpleTextAnalysis(text);
    return simpleAnalysis;
  }
};

// Enhanced rule-based emotion detection as fallback
const generateEmotions = (text: string, toxicityScore: number) => {
  const textLower = text.toLowerCase();
  const words = textLower.split(/\s+/);
  const emotions: Array<{ label: string; score: number }> = [];

  // Enhanced emotion lexicons with weighted words
  const emotionLexicon = {
    anger: {
      high: ['hate', 'furious', 'rage', 'bastard', 'asshole', 'fuck', 'bitch'],
      medium: ['angry', 'mad', 'annoyed', 'pissed', 'irritated', 'damn'],
      low: ['upset', 'frustrated', 'bothered', 'displeased']
    },
    sadness: {
      high: ['depressed', 'hopeless', 'devastated', 'miserable', 'worthless'],
      medium: ['sad', 'unhappy', 'disappointed', 'hurt', 'lonely'],
      low: ['down', 'blue', 'gloomy', 'sorry']
    },
    joy: {
      high: ['amazing', 'wonderful', 'fantastic', 'incredible', 'love'],
      medium: ['happy', 'great', 'good', 'nice', 'pleased'],
      low: ['okay', 'fine', 'alright', 'decent']
    },
    fear: {
      high: ['terrified', 'horrified', 'panic', 'dread'],
      medium: ['scared', 'afraid', 'anxious', 'worried', 'nervous'],
      low: ['concerned', 'uneasy', 'uncertain']
    },
    disgust: {
      high: ['disgusting', 'revolting', 'repulsive', 'vile'],
      medium: ['gross', 'nasty', 'sick', 'awful'],
      low: ['unpleasant', 'distasteful', 'icky']
    }
  };

  // Calculate emotion scores with weighted detection
  Object.entries(emotionLexicon).forEach(([emotion, levels]) => {
    let score = 0;
    let matchCount = 0;

    words.forEach(word => {
      if (levels.high.includes(word)) {
        score += 0.9;
        matchCount++;
      } else if (levels.medium.includes(word)) {
        score += 0.6;
        matchCount++;
      } else if (levels.low.includes(word)) {
        score += 0.3;
        matchCount++;
      }
    });

    // Normalize and boost based on toxicity for negative emotions
    if (matchCount > 0) {
      score = Math.min(1, score / Math.sqrt(words.length));
      if (['anger', 'disgust', 'fear'].includes(emotion)) {
        score = Math.max(score, toxicityScore * 0.7);
      }
    } else {
      // Base scores when no matches
      if (emotion === 'anger') score = toxicityScore * 0.5;
      else if (emotion === 'disgust') score = toxicityScore * 0.4;
      else if (emotion === 'joy') score = Math.max(0, 0.3 - toxicityScore * 0.3);
      else score = 0.1;
    }

    emotions.push({ label: emotion, score: Math.min(1, Math.max(0, score)) });
  });

  // Normalize scores to ensure they sum to approximately 1
  const totalScore = emotions.reduce((sum, e) => sum + e.score, 0);
  if (totalScore > 0) {
    emotions.forEach(e => e.score = e.score / totalScore);
  }

  return emotions.sort((a, b) => b.score - a.score);
};

// Enhanced rule-based text analysis with comprehensive pattern matching
const simpleTextAnalysis = (text: string) => {
  const textLower = text.toLowerCase();
  const words = textLower.split(/\s+/);
  
  // Comprehensive toxicity patterns with severity weights
  const toxicityPatterns = {
    severe: [
      'kill yourself', 'kys', 'end your life', 'should die', 'deserve to die',
      'kill you', 'rape', 'lynch', 'murder', 'terrorist', 'subhuman'
    ],
    high: [
      'hate you', 'fuck you', 'piece of shit', 'asshole', 'bastard',
      'bitch', 'whore', 'slut', 'retard', 'faggot', 'cunt'
    ],
    medium: [
      'hate', 'stupid', 'idiot', 'moron', 'dumb', 'loser', 
      'pathetic', 'worthless', 'useless', 'trash', 'garbage'
    ],
    low: [
      'shut up', 'annoying', 'awful', 'terrible', 'suck',
      'worst', 'disgusting', 'gross', 'nasty'
    ]
  };

  let toxicityScore = 0;
  const matchedPatterns = { severe: 0, high: 0, medium: 0, low: 0 };

  // Check for phrase patterns first (more severe)
  Object.entries(toxicityPatterns).forEach(([severity, patterns]) => {
    patterns.forEach(pattern => {
      if (textLower.includes(pattern)) {
        matchedPatterns[severity as keyof typeof matchedPatterns]++;
      }
    });
  });

  // Calculate weighted toxicity score
  toxicityScore = 
    (matchedPatterns.severe * 1.0) +
    (matchedPatterns.high * 0.7) +
    (matchedPatterns.medium * 0.4) +
    (matchedPatterns.low * 0.2);

  // Normalize by text length (longer texts get slightly adjusted)
  const lengthFactor = Math.min(1, words.length / 20);
  toxicityScore = Math.min(1, toxicityScore * (0.7 + lengthFactor * 0.3));

  // Check for ALL CAPS (aggressive tone)
  const capsRatio = (text.match(/[A-Z]/g) || []).length / text.length;
  if (capsRatio > 0.6 && text.length > 10) {
    toxicityScore = Math.min(1, toxicityScore * 1.2);
  }

  // Check for excessive punctuation (!!!, ???)
  const exclamationCount = (text.match(/!/g) || []).length;
  if (exclamationCount > 2) {
    toxicityScore = Math.min(1, toxicityScore * 1.1);
  }

  const isAbusive = toxicityScore > 0.4;
  
  let abuseType = undefined;
  if (isAbusive) {
    if (matchedPatterns.severe > 0 || toxicityScore > 0.85) {
      abuseType = 'Severe Harassment';
    } else if (matchedPatterns.high > 0 || toxicityScore > 0.7) {
      abuseType = 'Harassment';
    } else if (toxicityScore > 0.55) {
      abuseType = 'Hostile Language';
    } else {
      abuseType = 'Potentially Toxic';
    }
  }
  
  const emotions = generateEmotions(text, toxicityScore);
  
  let severity: 'safe' | 'low' | 'medium' | 'high' = 'safe';
  if (toxicityScore > 0.8 || matchedPatterns.severe > 0) {
    severity = 'high';
  } else if (toxicityScore > 0.6 || matchedPatterns.high > 0) {
    severity = 'medium';
  } else if (toxicityScore > 0.4) {
    severity = 'low';
  }
  
  return {
    isAbusive,
    abuseScore: toxicityScore,
    abuseType,
    emotions,
    severity,
  };
};
