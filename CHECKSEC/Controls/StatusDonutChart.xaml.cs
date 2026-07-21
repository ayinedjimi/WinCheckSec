using System;
using System.Collections.Generic;
using Microsoft.UI.Xaml;
using Microsoft.UI.Xaml.Controls;
using Microsoft.UI.Xaml.Controls.Primitives;
using Microsoft.UI.Xaml.Markup;
using Microsoft.UI.Xaml.Media;
using Microsoft.UI.Xaml.Shapes;
using WinRT;
using Windows.Foundation;
using Windows.UI;

namespace CHECKSEC.Controls;

public sealed partial class StatusDonutChart : UserControl
{
	public static readonly DependencyProperty OkCountProperty = DependencyProperty.Register("OkCount", typeof(int), typeof(StatusDonutChart), new PropertyMetadata(0, OnDataChanged));

	public static readonly DependencyProperty WarningCountProperty = DependencyProperty.Register("WarningCount", typeof(int), typeof(StatusDonutChart), new PropertyMetadata(0, OnDataChanged));

	public static readonly DependencyProperty CriticalCountProperty = DependencyProperty.Register("CriticalCount", typeof(int), typeof(StatusDonutChart), new PropertyMetadata(0, OnDataChanged));

	public static readonly DependencyProperty ErrorCountProperty = DependencyProperty.Register("ErrorCount", typeof(int), typeof(StatusDonutChart), new PropertyMetadata(0, OnDataChanged));

	public int OkCount
	{
		get
		{
			return (int)GetValue(OkCountProperty);
		}
		set
		{
			SetValue(OkCountProperty, value);
		}
	}

	public int WarningCount
	{
		get
		{
			return (int)GetValue(WarningCountProperty);
		}
		set
		{
			SetValue(WarningCountProperty, value);
		}
	}

	public int CriticalCount
	{
		get
		{
			return (int)GetValue(CriticalCountProperty);
		}
		set
		{
			SetValue(CriticalCountProperty, value);
		}
	}

	public int ErrorCount
	{
		get
		{
			return (int)GetValue(ErrorCountProperty);
		}
		set
		{
			SetValue(ErrorCountProperty, value);
		}
	}

	public StatusDonutChart()
	{
		InitializeComponent();
	}

	private static void OnDataChanged(DependencyObject d, DependencyPropertyChangedEventArgs e)
	{
		if (d is StatusDonutChart statusDonutChart)
		{
			statusDonutChart.DrawChart();
		}
	}

	private void DrawChart()
	{
		ChartCanvas.Children.Clear();
		int total = OkCount + WarningCount + CriticalCount + ErrorCount;
		if (total == 0)
		{
			return;
		}
		CenterText.Text = total.ToString();
		CenterLabel.Text = "vérifications";
		List<(int, Color)> segments = new List<(int, Color)>
		{
			(OkCount, Color.FromArgb(byte.MaxValue, 76, 175, 80)),
			(WarningCount, Color.FromArgb(byte.MaxValue, byte.MaxValue, 152, 0)),
			(CriticalCount, Color.FromArgb(byte.MaxValue, 244, 67, 54)),
			(ErrorCount, Color.FromArgb(byte.MaxValue, 120, 144, 156))
		};
		double startAngle = -90.0;
		double cx = 100.0;
		double cy = 100.0;
		double outerR = 85.0;
		double innerR = 55.0;
		foreach (var (count, color) in segments)
		{
			if (count != 0)
			{
				double sweepAngle = 360.0 * (double)count / (double)total;
				Path segment = CreateArcSegment(cx, cy, outerR, innerR, startAngle, sweepAngle, color);
				ChartCanvas.Children.Add(segment);
				startAngle += sweepAngle;
			}
		}
	}

	private static Path CreateArcSegment(double cx, double cy, double outerR, double innerR, double startAngleDeg, double sweepDeg, Color color)
	{
		if (sweepDeg >= 360.0)
		{
			sweepDeg = 359.99;
		}
		double startRad = startAngleDeg * Math.PI / 180.0;
		double endRad = (startAngleDeg + sweepDeg) * Math.PI / 180.0;
		bool isLargeArc = sweepDeg > 180.0;
		Point startPoint = new Point(cx + outerR * Math.Cos(startRad), cy + outerR * Math.Sin(startRad));
		Point outerEnd = new Point(cx + outerR * Math.Cos(endRad), cy + outerR * Math.Sin(endRad));
		Point innerEnd = new Point(cx + innerR * Math.Cos(endRad), cy + innerR * Math.Sin(endRad));
		Point innerStart = new Point(cx + innerR * Math.Cos(startRad), cy + innerR * Math.Sin(startRad));
		PathFigure pathFigure = new PathFigure
		{
			StartPoint = startPoint,
			IsClosed = true
		};
		pathFigure.Segments.Add(new ArcSegment
		{
			Point = outerEnd,
			Size = new Size(outerR, outerR),
			IsLargeArc = isLargeArc,
			SweepDirection = SweepDirection.Clockwise
		});
		pathFigure.Segments.Add(new LineSegment
		{
			Point = innerEnd
		});
		pathFigure.Segments.Add(new ArcSegment
		{
			Point = innerStart,
			Size = new Size(innerR, innerR),
			IsLargeArc = isLargeArc,
			SweepDirection = SweepDirection.Counterclockwise
		});
		PathGeometry pathGeometry = new PathGeometry();
		pathGeometry.Figures.Add(pathFigure);
		return new Path
		{
			Data = pathGeometry,
			Fill = new SolidColorBrush(color),
			Opacity = 0.9
		};
	}
}
