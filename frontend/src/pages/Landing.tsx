import { Link } from 'react-router-dom';
import { Shield, MessageSquare, BarChart3, Users } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '../components/ui/card';
import { useAuth } from '../hooks/useAuth';

const Landing = () => {
  const { user } = useAuth();

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Shield className="w-8 h-8 text-primary" />
            <h1 className="text-2xl font-bold">Safe Chat AI</h1>
          </div>
          <nav className="flex items-center gap-4">
            {user ? (
              <>
                <Link to="/chat">
                  <Button variant="ghost">Chat</Button>
                </Link>
                <Link to="/dashboard">
                  <Button variant="ghost">Dashboard</Button>
                </Link>
                <Link to="/profile">
                  <Button variant="ghost">Profile</Button>
                </Link>
              </>
            ) : (
              <Link to="/auth">
                <Button>Sign In</Button>
              </Link>
            )}
          </nav>
        </div>
      </header>

      {/* Hero Section */}
      <section className="container mx-auto px-4 py-20 text-center">
        <div className="max-w-3xl mx-auto space-y-6 animate-slide-up">
          <h2 className="text-5xl font-bold bg-gradient-primary bg-clip-text text-transparent">
            AI-Powered Message Moderation
          </h2>
          <p className="text-xl text-muted-foreground">
            Advanced machine learning technology to detect toxicity, analyze emotions, 
            and maintain healthy online communities in real-time.
          </p>
          <div className="flex gap-4 justify-center pt-4">
            {user ? (
              <Link to="/chat">
                <Button size="lg" className="shadow-glow">
                  Go to Chat
                </Button>
              </Link>
            ) : (
              <>
                <Link to="/auth">
                  <Button size="lg" className="shadow-glow">
                    Get Started
                  </Button>
                </Link>
                <Link to="/dashboard">
                  <Button size="lg" variant="outline">
                    View Demo
                  </Button>
                </Link>
              </>
            )}
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="container mx-auto px-4 py-16">
        <h3 className="text-3xl font-bold text-center mb-12">Powerful Features</h3>
        <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-6">
          <Card className="border-primary/20 hover:border-primary/40 transition-all hover:shadow-glow">
            <CardHeader>
              <MessageSquare className="w-12 h-12 text-primary mb-2" />
              <CardTitle>Real-Time Analysis</CardTitle>
            </CardHeader>
            <CardContent>
              <CardDescription>
                Instant ML-powered analysis of every message for toxicity, sentiment, and emotions.
              </CardDescription>
            </CardContent>
          </Card>

          <Card className="border-accent/20 hover:border-accent/40 transition-all">
            <CardHeader>
              <Shield className="w-12 h-12 text-accent mb-2" />
              <CardTitle>Abuse Detection</CardTitle>
            </CardHeader>
            <CardContent>
              <CardDescription>
                Identify harassment, hate speech, threats, and other harmful content automatically.
              </CardDescription>
            </CardContent>
          </Card>

          <Card className="border-warning/20 hover:border-warning/40 transition-all">
            <CardHeader>
              <BarChart3 className="w-12 h-12 text-warning mb-2" />
              <CardTitle>Detailed Analytics</CardTitle>
            </CardHeader>
            <CardContent>
              <CardDescription>
                Comprehensive dashboard with filtering, statistics, and moderation insights.
              </CardDescription>
            </CardContent>
          </Card>

          <Card className="border-success/20 hover:border-success/40 transition-all">
            <CardHeader>
              <Users className="w-12 h-12 text-success mb-2" />
              <CardTitle>Role Management</CardTitle>
            </CardHeader>
            <CardContent>
              <CardDescription>
                Complete user role system with admin, moderator, and user permissions.
              </CardDescription>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* Stats Section */}
      <section className="container mx-auto px-4 py-16">
        <div className="bg-card border border-border rounded-lg p-12">
          <div className="grid md:grid-cols-3 gap-8 text-center">
            <div>
              <div className="text-4xl font-bold text-primary mb-2">99.5%</div>
              <div className="text-muted-foreground">Accuracy Rate</div>
            </div>
            <div>
              <div className="text-4xl font-bold text-accent mb-2">&lt;100ms</div>
              <div className="text-muted-foreground">Analysis Time</div>
            </div>
            <div>
              <div className="text-4xl font-bold text-success mb-2">24/7</div>
              <div className="text-muted-foreground">Real-Time Protection</div>
            </div>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="container mx-auto px-4 py-20 text-center">
        <div className="max-w-2xl mx-auto space-y-6">
          <h3 className="text-3xl font-bold">Ready to Protect Your Community?</h3>
          <p className="text-lg text-muted-foreground">
            Join thousands of communities using AI-powered moderation to keep their spaces safe and welcoming.
          </p>
          {!user && (
            <Link to="/auth">
              <Button size="lg" className="shadow-glow">
                Start Free Trial
              </Button>
            </Link>
          )}
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border mt-20">
        <div className="container mx-auto px-4 py-8 text-center text-muted-foreground">
          <p>&copy; 2025 ModGuard AI. Built with ML technology.</p>
        </div>
      </footer>
    </div>
  );
};

export default Landing;
