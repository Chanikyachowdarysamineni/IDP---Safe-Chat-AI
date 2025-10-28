import { Badge } from './ui/badge';
import { Card } from './ui/card';
import { Progress } from './ui/progress';
import { AlertTriangle, CheckCircle, AlertOctagon, AlertCircle } from 'lucide-react';

interface MessageAnalysisProps {
  analysis: {
    isAbusive: boolean;
    abuseScore: number;
    abuseType?: string;
    emotions: Array<{ label: string; score: number }>;
    severity: 'safe' | 'low' | 'medium' | 'high';
  };
  // optional props to enable user feedback
  messageId?: string;
  content?: string;
}

const MessageAnalysis = ({ analysis, messageId, content }: MessageAnalysisProps) => {
  const getSeverityConfig = (severity: string) => {
    switch (severity) {
      case 'high':
        return {
          icon: AlertOctagon,
          color: 'text-destructive',
          bg: 'bg-destructive/10',
          border: 'border-destructive',
          label: 'High Risk',
        };
      case 'medium':
        return {
          icon: AlertTriangle,
          color: 'text-warning',
          bg: 'bg-warning/10',
          border: 'border-warning',
          label: 'Moderate Risk',
        };
      case 'low':
        return {
          icon: AlertCircle,
          color: 'text-accent',
          bg: 'bg-accent/10',
          border: 'border-accent',
          label: 'Low Risk',
        };
      default:
        return {
          icon: CheckCircle,
          color: 'text-success',
          bg: 'bg-success/10',
          border: 'border-success',
          label: 'Safe',
        };
    }
  };

  const getEmotionColor = (emotion: string) => {
    const emotionLower = emotion.toLowerCase();
    if (emotionLower.includes('anger') || emotionLower.includes('angry')) return 'hsl(var(--emotion-anger))';
    if (emotionLower.includes('joy') || emotionLower.includes('happy')) return 'hsl(var(--emotion-joy))';
    if (emotionLower.includes('sad')) return 'hsl(var(--emotion-sadness))';
    if (emotionLower.includes('fear')) return 'hsl(var(--emotion-fear))';
    if (emotionLower.includes('disgust')) return 'hsl(var(--emotion-disgust))';
    return 'hsl(var(--emotion-surprise))';
  };

  const severityConfig = getSeverityConfig(analysis.severity);
  const SeverityIcon = severityConfig.icon;

  return (
    <Card className={`p-4 border ${severityConfig.border} ${severityConfig.bg} space-y-3`}>
      {/* Severity Indicator */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <SeverityIcon className={`w-5 h-5 ${severityConfig.color}`} />
          <span className={`font-semibold ${severityConfig.color}`}>
            {severityConfig.label}
          </span>
        </div>
        {analysis.isAbusive && analysis.abuseType && (
          <Badge variant="destructive" className="bg-gradient-danger">
            {analysis.abuseType}
          </Badge>
        )}
      </div>

      {/* Abuse Detection */}
      <div className="space-y-2">
        <div className="flex items-center justify-between text-sm">
          <span className="text-muted-foreground">Toxicity Score</span>
          <span className={`font-semibold ${analysis.isAbusive ? 'text-destructive' : 'text-success'}`}>
            {Math.round(analysis.abuseScore * 100)}%
          </span>
        </div>
        <Progress 
          value={analysis.abuseScore * 100} 
          className="h-2"
        />
      </div>

      {/* Emotions */}
      {analysis.emotions.length > 0 && (
        <div className="space-y-2">
          <span className="text-sm text-muted-foreground">Detected Emotions</span>
          <div className="space-y-2">
            {analysis.emotions
              .filter((emotion) => emotion.score > 0.1)
              .sort((a, b) => b.score - a.score)
              .slice(0, 3)
              .map((emotion, idx) => (
                <div key={idx} className="space-y-1">
                  <div className="flex items-center justify-between text-sm">
                    <div className="flex items-center gap-2">
                      <div 
                        className="w-3 h-3 rounded-full"
                        style={{ backgroundColor: getEmotionColor(emotion.label) }}
                      />
                      <span className="capitalize">{emotion.label}</span>
                    </div>
                    <span className="font-semibold">{Math.round(emotion.score * 100)}%</span>
                  </div>
                  <Progress 
                    value={emotion.score * 100} 
                    className="h-1.5"
                  />
                </div>
              ))}
          </div>
        </div>
      )}

      {/* Alert Message */}
      {analysis.severity === 'high' && (
        <div className="pt-2 border-t border-destructive/20">
          <p className="text-xs text-destructive font-medium">
            ⚠️ This message has been flagged for moderator review
          </p>
        </div>
      )}

      {/* Feedback / Annotation */}
      {messageId && (
        <div className="pt-2 border-t">
          <button
            className="text-sm text-muted-foreground underline"
            onClick={async () => {
              try {
                const note = window.prompt('Tell us what was wrong with the analysis (short):');
                if (!note) return;
                const token = await window.storage.getItem('token');
                await fetch('/api/annotations', {
                  method: 'POST',
                  headers: {
                    'Content-Type': 'application/json',
                    ...(token ? { Authorization: `Bearer ${token}` } : {}),
                  },
                  body: JSON.stringify({
                    message_id: messageId,
                    content: content || null,
                    labels: { feedback: note },
                    source: 'user',
                  }),
                });
                window.alert('Thanks — feedback submitted');
              } catch (err) {
                console.error('Feedback error', err);
                window.alert('Failed to submit feedback');
              }
            }}
          >
            Report incorrect analysis
          </button>
        </div>
      )}
    </Card>
  );
};

export default MessageAnalysis;
